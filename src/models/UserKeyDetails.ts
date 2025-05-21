import { Model, DataTypes, Optional } from 'sequelize';
import sequelize from '../config/database';

interface UserKeyDetailsAttributes {
    id: number;
    locationId: string;
    keyRingId: string;
    keyId: string;
    secretId: string;
    userId: number;
    createdAt?: Date;
    updatedAt?: Date;
}

interface UserKeyDetailsCreationAttributes extends Optional<UserKeyDetailsAttributes, 'id'> { }

class UserKeyDetails extends Model<UserKeyDetailsAttributes, UserKeyDetailsCreationAttributes> implements UserKeyDetailsAttributes {
    public id!: number;
    public locationId!: string;
    public keyRingId!: string;
    public keyId!: string;
    public secretId!: string;
    public userId!: number;
    public readonly createdAt!: Date;
    public readonly updatedAt!: Date;
}

UserKeyDetails.init({
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    locationId: {
        type: DataTypes.STRING,
        allowNull: false
    },
    keyRingId: {
        type: DataTypes.STRING,
        allowNull: false
    },
    keyId: {
        type: DataTypes.STRING,
        allowNull: false
    },
    secretId: {
        type: DataTypes.STRING,
        allowNull: false
    },
    userId: {
        type: DataTypes.INTEGER,
        allowNull: false
    }
}, {
    sequelize,
    timestamps: true,
    tableName: 'UserKeyDetails'
});

export default UserKeyDetails; 