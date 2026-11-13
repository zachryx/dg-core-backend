import {
  Injectable,
  Logger,
  NotFoundException,
  OnModuleInit,
} from "@nestjs/common";
import { UsersRepository } from "../users/users.repository";
import { Types, UpdateQuery } from "mongoose";
import { APP_ROLES } from "../../../common/interfaces/auth.interface";
import { FetchUsersQueryDto } from "./dtos/query.dto";
import { User } from "../users/schemas/user.schema";
import { BusinessRepository } from "../business/business.repository";
import { ForumsRepository } from "../forums/forums.repository";
import { UpdateForumDto } from "./dtos/update-forum.dto";
import { MailerService } from "@nestjs-modules/mailer";
import { ConfigService } from "@nestjs/config";
import * as bcrypt from "bcrypt";

@Injectable()
export class AdminService implements OnModuleInit {
  private readonly logger = new Logger(AdminService.name);

  constructor(
    private readonly usersRepository: UsersRepository,
    private readonly businessRepository: BusinessRepository,
    private readonly forumsRepository: ForumsRepository,
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService
  ) {}

  async onModuleInit(): Promise<void> {
    await this.initializeSuperAdmin();
  }

  async initializeSuperAdmin(): Promise<void> {
    try {
      const adminEmail = this.configService.get<string>("ADMIN_EMAIL");
      const adminPassword = this.configService.get<string>("ADMIN_PASSWORD");

      if (!adminEmail || !adminPassword) {
        this.logger.warn(
          "ADMIN_EMAIL or ADMIN_PASSWORD not set in environment variables. Skipping super admin initialization."
        );
        return;
      }

      // Email is unique across all roles, so look up by email alone
      const existingUser = await this.usersRepository.findOne({
        email: adminEmail,
      });

      if (existingUser) {
        if (existingUser.role === APP_ROLES.ADMIN) {
          this.logger.log(
            `Super admin account already exists with email: ${adminEmail}`
          );
        } else {
          // Never promote automatically: that account's password was not set from ADMIN_PASSWORD
          this.logger.warn(
            `ADMIN_EMAIL (${adminEmail}) belongs to an existing "${existingUser.role}" account. Super admin was NOT created. Use a different ADMIN_EMAIL or change that account's role manually.`
          );
        }
        return;
      }

      // Create super admin account
      const saltRounds = Number(
        this.configService.get<number>("SALT_ROUND") || 10
      );
      const salt = await bcrypt.genSalt(saltRounds);
      const hashedPassword = await bcrypt.hash(adminPassword, salt);

      await this.usersRepository.create({
        email: adminEmail,
        password: hashedPassword,
        role: APP_ROLES.ADMIN,
        fullname: "Super Admin",
        isVerified: true,
        isActive: true,
      });

      this.logger.log(
        `Super admin account created successfully with email: ${adminEmail}`
      );
    } catch (error) {
      this.logger.error(
        `Failed to initialize super admin account: ${error.message}`,
        error.stack
      );
    }
  }

  async approveCreatorAccount(_id: Types.ObjectId) {
    const user = await this.usersRepository.findOne({
      _id,
      role: APP_ROLES.CREATOR,
    });

    if (!user) {
      throw new NotFoundException("Creator account does not exist");
    }

    await this.businessRepository.findOneAndUpdate(
      { _id: user.business._id },
      { isApproved: true }
    );

    const appUrl = this.configService.getOrThrow("CLIENT_URL");
    const url = `${appUrl}/login`;

    await this.mailerService.sendMail({
      to: user.email,
      subject: "Account Approval",
      template: "account_approval",
      context: {
        name: user.fullname.split(" ")[0],
        url,
      },
    });

    return user;
  }

  async retrieveUsers(query: FetchUsersQueryDto) {
    const { page, limit, ...rest } = query;

    const parsedFilter = this.parseFilter(rest);

    return this.usersRepository.find({ ...parsedFilter }, null, {
      page,
      skip: (page - 1) * limit,
      sort: "-createdAt",
    });
  }

  async retrieveUser(_id: Types.ObjectId) {
    return this.usersRepository.findOne({ _id });
  }

  async updateUserAccount(_id: Types.ObjectId, payload: UpdateQuery<User>) {
    return this.usersRepository.findOneAndUpdate({ _id }, payload);
  }

  async findForums(query: any) {
    const { page, limit, ...rest } = query;

    const parsedFilter = this.parseFilter(rest);

    return this.forumsRepository.find({ ...parsedFilter }, null, {
      page,
      skip: (page - 1) * limit,
      sort: "-createdAt -updatedAt",
    });
  }

  async approveForum(_id: Types.ObjectId, payload: UpdateForumDto) {
    const forum = await this.forumsRepository.findOneAndUpdate(
      { _id },
      { ...payload }
    );

    const user = await this.usersRepository.findOne({ _id: forum.creator });

    await this.mailerService.sendMail({
      to: user.email,
      subject: "Forum Approval",
      template: "forum_approval",
      context: {
        title: forum.title,
      },
    });

    return forum;
  }

  private parseFilter(query: Partial<any>): object {
    const filter = {};

    if (query.category) {
      Object.assign(filter, { categories: { $in: [query.category] } });
    }

    if (query.search) {
      Object.assign(filter, { title: { $regex: query.search, $options: "i" } });
    }

    if (query.section) {
      Object.assign(filter, { sections: { $in: [query.section] } });
    }

    if (query.category) {
      Object.assign(filter, { category: query.category });
    }

    if (query.rating) {
      Object.assign(filter, { rating: { $gte: query.rating } });
    }

    if (query.role) {
      Object.assign(filter, { role: query.role });
    }

    if (query.approvalStatus) {
      Object.assign(filter, { approved: query.approvalStatus });
    }

    if (query.date) {
      const startDate = new Date(query.date);
      startDate.setHours(0, 0, 0, 0);
      const endDate = new Date(query.date);
      endDate.setHours(23, 59, 59, 59);

      Object.assign(filter, { createdAt: { $gte: startDate, $lte: endDate } });
    }

    return filter;
  }
}
