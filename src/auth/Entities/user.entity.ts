import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ default: false })
  is_active?: boolean;

  @Column({ nullable: true })
  activated_token?: string;

  @Column({ nullable: true })
  activated_token_expiration?: Date;

  @Column({ nullable: true })
  reset_token?: string;

  @Column({ nullable: true })
  reset_token_expiration?: Date;

  @Column({ nullable: true })
  token?: string;
}
