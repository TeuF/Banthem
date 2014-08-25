SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: 'banthem'
--

-- --------------------------------------------------------

--
-- Table structure for table 'ips'
--

CREATE TABLE ips (
  id int(11) NOT NULL AUTO_INCREMENT,
  address varchar(255) DEFAULT NULL,
  `type` int(11) DEFAULT NULL,
  country varchar(255) DEFAULT NULL,
  city varchar(255) DEFAULT NULL,
  country_code varchar(255) DEFAULT NULL,
  latitude float DEFAULT NULL,
  longitude float DEFAULT NULL,
  isp varchar(255) DEFAULT NULL,
  timezone varchar(255) DEFAULT NULL,
  created_at datetime DEFAULT NULL,
  updated_at datetime DEFAULT NULL,
  attacker tinyint(1) DEFAULT NULL,
  `client` tinyint(1) DEFAULT NULL,
  bck tinyint(1) DEFAULT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table 'T_CLIENT'
--

CREATE TABLE T_CLIENT (
  CLT_ID int(11) NOT NULL AUTO_INCREMENT COMMENT 'Client ID',
  IP_ID int(11) NOT NULL COMMENT 'IP Id',
  CLT_CRD char(64) NOT NULL COMMENT 'Client Pwd',
  EMAIL varchar(64) NOT NULL,
  UID char(64) NOT NULL COMMENT 'Api key',
  CRT_TIME timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PUSH_TIME timestamp NULL DEFAULT NULL,
  MGT_TIME timestamp NULL DEFAULT NULL,
  TOKEN char(64) DEFAULT NULL,
  PRIMARY KEY (CLT_ID),
  KEY uid (UID)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COMMENT='Client Table';

-- --------------------------------------------------------

--
-- Table structure for table 'T_FILE'
--

CREATE TABLE T_FILE (
  FILE_ID int(11) NOT NULL AUTO_INCREMENT,
  FMD5 char(32) NOT NULL,
  FSHA char(64) NOT NULL,
  FSSDEEP varchar(128) NOT NULL,
  PRIMARY KEY (FILE_ID)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table 'T_HIT'
--

CREATE TABLE T_HIT (
  HIT_ID int(11) NOT NULL AUTO_INCREMENT,
  CLT_ID int(11) NOT NULL,
  INJ_ID int(11) NOT NULL,
  TYPE_ID int(11) NOT NULL DEFAULT '1',
  MURL_ID int(11) DEFAULT NULL,
  FILE_ID int(11) DEFAULT NULL,
  HIT_TIME timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (HIT_ID)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table 'T_INJ'
--

CREATE TABLE T_INJ (
  INJ_ID int(11) NOT NULL AUTO_INCREMENT,
  INJ_HIT varchar(8192) NOT NULL,
  PRIMARY KEY (INJ_ID)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table 'T_MURL'
--

CREATE TABLE T_MURL (
  MURL_ID int(11) NOT NULL AUTO_INCREMENT,
  MURL varchar(8196) NOT NULL,
  PRIMARY KEY (MURL_ID)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table 'T_TYPE'
--

CREATE TABLE T_TYPE (
  TYPE_ID int(11) NOT NULL AUTO_INCREMENT,
  `DESC` varchar(32) NOT NULL,
  PRIMARY KEY (TYPE_ID)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COMMENT='Attack Type';
}
}
