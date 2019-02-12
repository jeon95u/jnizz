drop table if exists crash;
create table crash (
    id integer primary key autoincrement,
    pkg_name text not null,
    tomb_txt text not null,
    crashed_func_name text not null,
    args text not null,
    exploitable text not null,
    time text not null
);