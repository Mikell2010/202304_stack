-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema db_base_examen
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema db_base_examen
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `db_base_examen` DEFAULT CHARACTER SET utf8 ;
USE `db_base_examen` ;

-- -----------------------------------------------------
-- Table `db_base_examen`.`usuarios`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `db_base_examen`.`usuarios` (
`id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
`nombre` VARCHAR(145) NOT NULL,
`apellido` VARCHAR(145) NOT NULL,
`email` VARCHAR(200) NULL,
`password` VARCHAR(250) NULL,
`created_at` DATETIME NULL,
`updated_at` DATETIME NULL,
PRIMARY KEY (`id`),
UNIQUE INDEX `email_UNIQUE` (`email` ASC) VISIBLE)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `db_base_examen`.`recetas`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `db_base_examen`.`recetas` (
`id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
`nombre` VARCHAR(145) NOT NULL,
`descripcion` TEXT NULL,
`instrucciones` VARCHAR(45) NULL,
`bajo_tiempo` TINYINT NULL,
`fecha_cocinado` DATETIME NULL,
`usuario_id` INT UNSIGNED NOT NULL,
`created_at` DATETIME NULL,
`updated_at` DATETIME NULL,
PRIMARY KEY (`id`),
INDEX `fk_recetas_usuarios_idx` (`usuario_id` ASC) VISIBLE,
CONSTRAINT `fk_recetas_usuarios`
    FOREIGN KEY (`usuario_id`)
    REFERENCES `db_base_examen`.`usuarios` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;