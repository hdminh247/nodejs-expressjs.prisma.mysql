import { NextFunction, Request, Response } from "express";

import { verify } from "../../utils/jwt";
import HttpResponse from "../../services/response";

import { prisma } from "@/prisma/client";

export const verifyToken = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization;

    if (token) {
      try {
        const verifiedInfo: any = verify(token.split(" ")[1]);

        // Get user info
        req["user"] = await prisma.user.findUnique({ where: { id: verifiedInfo.id }, include: { role: true } });
        await next();
      } catch (err: any) {
        console.log(err);
        return HttpResponse.returnUnAuthorizeResponse(res, "auth.token.invalid");
      }
    } else {
      return HttpResponse.returnUnAuthorizeResponse(res, "auth.token.invalid");
    }
  };
};
