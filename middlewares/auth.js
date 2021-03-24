const User = require('../models/user')

const jwt = require("jsonwebtoken");
const ErrorHandler = require("../utils/errorHandler");
const catchAsyncErrors = require("./catchAsyncErrors");

// Checks if user is authenticated or not
exports.isAuthenticatedUser = catchAsyncErrors(async (req, res, next) => {

    const { token } = req.cookies

    if (!token) {
        return next(new ErrorHandler('Bu resurs əlçatan deyil. Zəhmət olmasa, daxil olun', 401))
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = await User.findById(decoded.id);

    next()
})

// Handling users roles
exports.authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(
                new ErrorHandler(`Rol (${req.user.role}) bu resursa çatmaq üçün səlahiyyətə malik deyil!...`, 403))
        }
        next()
    }
}