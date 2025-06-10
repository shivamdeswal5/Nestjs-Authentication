import {Column, Entity, PrimaryGeneratedColumn, ManyToOne, JoinColumn, CreateDateColumn} from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { OTPType } from '../../otp/type/otpType';

@Entity()
export class OTP{
    @PrimaryGeneratedColumn()
    id: number;

    @ManyToOne(type => User, {nullable:false})
    @JoinColumn()
    user: User;

    @Column()
    token: string;

    @Column({type:'enum', enum:OTPType})
    type: OTPType;

    @Column()
    expiresAt: Date;

    @CreateDateColumn()
    createdAt: Date;
}