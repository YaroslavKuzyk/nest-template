import {
  ValidationPipe,
  ValidationError,
  UnprocessableEntityException,
} from '@nestjs/common';

export class CustomValidationPipe extends ValidationPipe {
  protected flattenValidationErrors(
    validationErrors: ValidationError[],
  ): any[] {
    return validationErrors.flatMap((error) => {
      if (error.children && error.children.length > 0) {
        return this.flattenValidationErrors(error.children);
      }

      return {
        field: error.property,
        errors: Object.values(error.constraints || {}),
      };
    });
  }

  createExceptionFactory() {
    return (validationErrors: ValidationError[] = []) => {
      const errors = this.flattenValidationErrors(validationErrors);
      return new UnprocessableEntityException(errors);
    };
  }
}
