import { PrismaClient } from "@prisma/client";
import encryption from "../../utils/encryption";
const prisma = new PrismaClient();
async function main() {
  await prisma.role.createMany({
    data: [
      {
        name: "user",
      },
      {
        name: "admin",
      },
    ],
  });
  await prisma.user.createMany({
    data: [
      {
        email: "admin@test.com",
        password: encryption.hashPassword("Admin123@test!^"),
        first_name: "Admin",
        last_name: "Admin",
        role_id: 1,
      },
    ],
  });
}
main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
