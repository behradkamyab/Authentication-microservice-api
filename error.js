exports.errorHandling = async (error, statusCode) => {
  let err = new Error(error);
  err.message = error;
  err.statusCode = statusCode;
  return err;
};
