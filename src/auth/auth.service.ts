import { Injectable, ForbiddenException } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import * as argon from "argon2";

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  signToken(userId: number, email: string): Promise<string> {
    const payload = {
      sub: userId,
      email,
    };

    return this.jwt.signAsync(payload, {
      expiresIn: "15m", // 15 minutes
      secret: this.config.get("JWT_SECRET"),
    });
  }

  async signup(dto: AuthDto): Promise<{ access_token: string }> {
    // generate the password hash
    const hash = await argon.hash(dto.password);

    try {
      // save the new user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      // send back the access_token
      return {
        access_token: await this.signToken(user.id, user.email),
      };
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === "P2002") {
          throw new ForbiddenException("Credentials taken");
        }
      }

      throw err;
    }
  }

  async signin(dto: AuthDto): Promise<{ access_token: string }> {
    // find user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // if user does not exist throw exception
    if (!user) throw new ForbiddenException("Credentials incorrect");

    // compare password
    const pwMatches = await argon.verify(user.hash, dto.password);
    // if password is incorrect throw exception
    if (!pwMatches) throw new ForbiddenException("Credentials incorrect");

    // send back the access_token
    return {
      access_token: await this.signToken(user.id, user.email),
    };
  }
}
