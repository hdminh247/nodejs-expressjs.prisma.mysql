export const format = (value: number) => {
  return value.toFixed(2).replace(/\d(?=(\d{3})+\.)/g, "$&,");
};
