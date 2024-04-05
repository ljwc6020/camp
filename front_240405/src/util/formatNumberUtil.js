export const formatNumber = (num) => {
  if (num === 0) return "0";
  let regex = /(^[+-]?\d+)(\d{3})/;
  let nstr = num.toString();
  while (regex.test(nstr)) {
    nstr = nstr.replace(regex, "$1" + "," + "$2");
  }
  return nstr;
};
