import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({default:'unverified'})
  accountStatus: 'verified' | 'unverified';

  @Column({ type: 'varchar',  nullable: true })
  profileImg: string

  @Column({type: 'varchar',nullable:true})
  refreshToken: string

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
 
}
