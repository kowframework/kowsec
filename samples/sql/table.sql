

drop database if exists aw_sec_samples;
create database if not exists aw_sec_samples;
use aw_sec_samples;

drop table if exists Users;
drop table if exists Groups;

create table Users (
    id int(10) unsigned not null auto_increment,
    Username VARCHAR(20),
    Password VARCHAR(20),
    First_Name VARCHAR(20),
    Last_Name VARCHAR(50),
    primary key (id),
    unique key(Username)
);


create table Groups (
    Username VARCHAR(20) not null,
    Group_Name VARCHAR(20) not null,
    primary key(Username,Group_Name)
);


SELECT * FROM Users;
INSERT INTO Users(Username,Password,First_Name,Last_Name) VALUES('OgRo','passworded','Marcelo','Coraça de Freitas');

INSERT INTO Groups(Username,Group_Name) VALUES('OgRo', 'dev');
INSERT INTO Groups(Username,Group_Name) VALUES('OgRo', 'users');

INSERT INTO Groups(Username,Group_Name) VALUES('adele', 'users');



drop database if exists aw_sec_samples_another_db;
create database if not exists aw_sec_samples_another_db;
use aw_sec_samples_another_db;

drop table if exists Users;
drop table if exists Groups;

create table Users (
    id int(10) unsigned not null auto_increment,
    Username VARCHAR(20),
    Password VARCHAR(20),
    First_Name VARCHAR(20),
    Last_Name VARCHAR(50),
    primary key (id),
    unique key(Username)
);


create table Groups (
    Username VARCHAR(20) not null,
    Group_Name VARCHAR(20) not null,
    primary key(Username,Group_Name)
);


SELECT * FROM Users;
INSERT INTO Users(Username,Password,First_Name,Last_Name) VALUES('adele','passworded','Adèle','Ribeiro');

INSERT INTO Groups(Username,Group_Name) VALUES('OgRo', 'admin');

INSERT INTO Groups(Username,Group_Name) VALUES('adele', 'dev');
