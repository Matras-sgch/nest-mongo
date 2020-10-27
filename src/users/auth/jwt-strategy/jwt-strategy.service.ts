import { Injectable, UnauthorizedException } from '@nestjs/common';
import {PassportStrategy} from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { jwtConstant } from '../../../constants/jwt.constants';
import { UsersService } from '../../users.service';

@Injectable()
export class JwtStrategyService extends PassportStrategy(Strategy) {
    constructor(
        private userServise: UsersService
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: jwtConstant.secret,
        });
    }

    async validate(payload: any) {
        // find the user based on id from the payload.id
        const isValidated = await this.userServise.validateUserById(payload.id)
        if (isValidated) {
            return { userId: payload.id, email: payload.email }
        } else {
            return new  UnauthorizedException('UnAuthorized')
        }
    }
}
