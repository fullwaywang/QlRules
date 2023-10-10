/**
 * @name postgresql-5579726bd60a6e7afb04a3548bced348cd5ffd89-CollationCreate
 * @id cpp/postgresql/5579726bd60a6e7afb04a3548bced348cd5ffd89/CollationCreate
 * @description postgresql-5579726bd60a6e7afb04a3548bced348cd5ffd89-src/backend/catalog/pg_collation.c-CollationCreate CVE-2022-2625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcollname_46, Parameter vcollnamespace_46, Parameter vcollencoding_50, Variable void_64, ExprStmt target_36, LogicalOrExpr target_33, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=void_64
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetSysCacheOid")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof EnumConstantAccess
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcollname_46
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcollencoding_50
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vcollnamespace_46
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_3(Variable vmyself_65, VariableAccess target_38) {
	exists(DoStmt target_3 |
		target_3.getCondition().(Literal).getValue()="0"
		and target_3.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_3.getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_3.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_3.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_3.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38)
}

/*predicate func_4(Variable vmyself_65, LogicalOrExpr target_33) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33)
}

*/
predicate func_5(Variable vmyself_65, VariableAccess target_38) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmyself_65
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38)
}

predicate func_6(Parameter vcollname_46, Parameter vcollnamespace_46, Variable void_64, LogicalOrExpr target_33, ExprStmt target_40, FunctionCall target_32) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=void_64
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetSysCacheOid")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof EnumConstantAccess
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcollname_46
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3) instanceof FunctionCall
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vcollnamespace_46
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5) instanceof Literal
		and target_6.getParent().(IfStmt).getCondition()=target_33
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_32.getArgument(3).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

predicate func_7(Parameter vcollname_46, Parameter vcollnamespace_46, Variable void_64, LogicalOrExpr target_33, ExprStmt target_41, ExprStmt target_42) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=void_64
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetSysCacheOid")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof EnumConstantAccess
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcollname_46
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3) instanceof UnaryMinusExpr
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vcollnamespace_46
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5) instanceof Literal
		and target_7.getParent().(IfStmt).getCondition()=target_33
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_41.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_42.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vif_not_exists_53, Parameter vquiet_54, Variable vrel_56, Variable void_64, IfStmt target_43, IfStmt target_44, ExprStmt target_45, ExprStmt target_46, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=void_64
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vquiet_54
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_56
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(VariableAccess).getTarget()=vif_not_exists_53
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(DoStmt).getCondition() instanceof Literal
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_8)
		and target_43.getCondition().(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(VariableAccess).getLocation())
		and target_44.getCondition().(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getLocation())
		and target_45.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_9(Variable void_64, Variable vmyself_65, VariableAccess target_47) {
	exists(DoStmt target_9 |
		target_9.getCondition().(Literal).getValue()="0"
		and target_9.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_9.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_9.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3456"
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=void_64
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_47)
}

*/
/*predicate func_10(Variable vmyself_65, VariableAccess target_47) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmyself_65
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_47)
}

*/
predicate func_12(Variable void_64, Variable vmyself_65, ExprStmt target_48, ExprStmt target_15, ExprStmt target_14, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=void_64
		and (func.getEntryPoint().(BlockStmt).getStmt(38)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(38).getFollowingStmt()=target_12)
		and target_48.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_13(Function func, UnaryMinusExpr target_13) {
		target_13.getValue()="-1"
		and target_13.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_13.getEnclosingFunction() = func
}

predicate func_14(Variable vmyself_65, Function func, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_14.getExpr().(AssignExpr).getRValue().(Literal).getValue()="3456"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Variable void_64, Variable vmyself_65, Function func, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_15.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=void_64
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_15
}

predicate func_16(Parameter vcollencoding_50, EqualityOperation target_16) {
		target_16.getAnOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_16.getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

predicate func_18(Parameter vcollname_46, Parameter vcollnamespace_46, Parameter vcollencoding_50, BlockStmt target_49, VariableAccess target_18) {
		target_18.getTarget()=vcollname_46
		and target_18.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcollencoding_50
		and target_18.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcollnamespace_46
		and target_18.getParent().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_18.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_49
}

/*predicate func_19(Parameter vcollname_46, Parameter vcollnamespace_46, Parameter vcollencoding_50, BlockStmt target_49, VariableAccess target_19) {
		target_19.getTarget()=vcollencoding_50
		and target_19.getParent().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_46
		and target_19.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcollnamespace_46
		and target_19.getParent().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_19.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_49
}

*/
/*predicate func_20(Parameter vcollname_46, Parameter vcollnamespace_46, Parameter vcollencoding_50, BlockStmt target_49, VariableAccess target_20) {
		target_20.getTarget()=vcollnamespace_46
		and target_20.getParent().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_46
		and target_20.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcollencoding_50
		and target_20.getParent().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_20.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_49
}

*/
predicate func_23(Parameter vcollname_46, VariableAccess target_23) {
		target_23.getTarget()=vcollname_46
		and target_23.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_24(Function func, FunctionCall target_24) {
		target_24.getTarget().hasName("GetDatabaseEncoding")
		and target_24.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_24.getEnclosingFunction() = func
}

predicate func_25(Parameter vcollnamespace_46, VariableAccess target_25) {
		target_25.getTarget()=vcollnamespace_46
		and target_25.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_28(Parameter vcollname_46, VariableAccess target_28) {
		target_28.getTarget()=vcollname_46
		and target_28.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_29(Parameter vcollnamespace_46, VariableAccess target_29) {
		target_29.getTarget()=vcollnamespace_46
		and target_29.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_32(Parameter vcollname_46, Parameter vcollnamespace_46, Parameter vcollencoding_50, BlockStmt target_49, FunctionCall target_32) {
		target_32.getTarget().hasName("SearchSysCacheExists")
		and target_32.getArgument(0) instanceof EnumConstantAccess
		and target_32.getArgument(1).(VariableAccess).getTarget()=vcollname_46
		and target_32.getArgument(2).(VariableAccess).getTarget()=vcollencoding_50
		and target_32.getArgument(3).(VariableAccess).getTarget()=vcollnamespace_46
		and target_32.getArgument(4) instanceof Literal
		and target_32.getParent().(IfStmt).getThen()=target_49
}

predicate func_33(Parameter vcollname_46, Parameter vcollnamespace_46, Parameter vcollencoding_50, BlockStmt target_50, LogicalOrExpr target_33) {
		target_33.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("SearchSysCacheExists")
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0) instanceof EnumConstantAccess
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_46
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcollnamespace_46
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(4) instanceof Literal
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("SearchSysCacheExists")
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0) instanceof EnumConstantAccess
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_46
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2) instanceof UnaryMinusExpr
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcollnamespace_46
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(4) instanceof Literal
		and target_33.getParent().(IfStmt).getThen()=target_50
}

/*predicate func_34(Parameter vcollencoding_50, LogicalOrExpr target_33, ExprStmt target_51, VariableAccess target_34) {
		target_34.getTarget()=vcollencoding_50
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_34.getLocation())
		and target_34.getLocation().isBefore(target_51.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

*/
/*predicate func_35(Function func, UnaryMinusExpr target_35) {
		target_35.getValue()="-1"
		and target_35.getEnclosingFunction() = func
}

*/
predicate func_36(Parameter vcollname_46, Parameter vcollencoding_50, ExprStmt target_36) {
		target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("errcode")
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(AddExpr).getValue()="290948"
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("errmsg")
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(StringLiteral).getValue()="collation \"%s\" already exists, skipping"
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_46
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("errmsg")
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(StringLiteral).getValue()="collation \"%s\" for encoding \"%s\" already exists, skipping"
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_46
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("pg_encoding_to_char")
		and target_36.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcollencoding_50
		and target_36.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_36.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof Literal
}

predicate func_38(Parameter vif_not_exists_53, VariableAccess target_38) {
		target_38.getTarget()=vif_not_exists_53
}

predicate func_40(Parameter vcollname_46, Parameter vcollencoding_50, ExprStmt target_40) {
		target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("errcode")
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(AddExpr).getValue()="290948"
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("errmsg")
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(StringLiteral).getValue()="collation \"%s\" already exists"
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_46
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("errmsg")
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(StringLiteral).getValue()="collation \"%s\" for encoding \"%s\" already exists"
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_46
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("pg_encoding_to_char")
		and target_40.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcollencoding_50
		and target_40.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_40.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof Literal
}

predicate func_41(Parameter vcollname_46, ExprStmt target_41) {
		target_41.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("errcode")
		and target_41.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(AddExpr).getValue()="290948"
		and target_41.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errmsg")
		and target_41.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="collation \"%s\" already exists, skipping"
		and target_41.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_46
		and target_41.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_41.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof Literal
}

predicate func_42(Parameter vcollnamespace_46, ExprStmt target_42) {
		target_42.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("Datum[10]")
		and target_42.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getValue()="2"
		and target_42.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcollnamespace_46
}

predicate func_43(Parameter vif_not_exists_53, IfStmt target_43) {
		target_43.getCondition().(VariableAccess).getTarget()=vif_not_exists_53
		and target_43.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_43.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_43.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_43.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_43.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_43.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_43.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_43.getElse().(DoStmt).getCondition() instanceof Literal
		and target_43.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_43.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_43.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_43.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_43.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_43.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_43.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
}

predicate func_44(Parameter vif_not_exists_53, Parameter vquiet_54, IfStmt target_44) {
		target_44.getCondition().(VariableAccess).getTarget()=vquiet_54
		and target_44.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_44.getElse().(IfStmt).getCondition().(VariableAccess).getTarget()=vif_not_exists_53
		and target_44.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_44.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_44.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_44.getElse().(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and target_44.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_44.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_44.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_44.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_44.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_44.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_45(Variable vrel_56, ExprStmt target_45) {
		target_45.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrel_56
		and target_45.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("table_open")
		and target_45.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="3456"
		and target_45.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="6"
}

predicate func_46(Variable vrel_56, ExprStmt target_46) {
		target_46.getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_56
		and target_46.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_47(Parameter vif_not_exists_53, VariableAccess target_47) {
		target_47.getTarget()=vif_not_exists_53
}

predicate func_48(Variable void_64, ExprStmt target_48) {
		target_48.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("Datum[10]")
		and target_48.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getValue()="0"
		and target_48.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=void_64
}

predicate func_49(Parameter vif_not_exists_53, Parameter vquiet_54, BlockStmt target_49) {
		target_49.getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vquiet_54
		and target_49.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_49.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(VariableAccess).getTarget()=vif_not_exists_53
		and target_49.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_49.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_49.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and target_49.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
}

predicate func_50(Parameter vif_not_exists_53, Parameter vquiet_54, Variable vrel_56, BlockStmt target_50) {
		target_50.getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vquiet_54
		and target_50.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_50.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_56
		and target_50.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_50.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_50.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(VariableAccess).getTarget()=vif_not_exists_53
		and target_50.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_50.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_56
		and target_50.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_50.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_50.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_50.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and target_50.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
}

predicate func_51(Parameter vcollencoding_50, ExprStmt target_51) {
		target_51.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("Datum[10]")
		and target_51.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getValue()="6"
		and target_51.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcollencoding_50
}

from Function func, Parameter vcollname_46, Parameter vcollnamespace_46, Parameter vcollencoding_50, Parameter vif_not_exists_53, Parameter vquiet_54, Variable vrel_56, Variable void_64, Variable vmyself_65, UnaryMinusExpr target_13, ExprStmt target_14, ExprStmt target_15, EqualityOperation target_16, VariableAccess target_18, VariableAccess target_23, FunctionCall target_24, VariableAccess target_25, VariableAccess target_28, VariableAccess target_29, FunctionCall target_32, LogicalOrExpr target_33, ExprStmt target_36, VariableAccess target_38, ExprStmt target_40, ExprStmt target_41, ExprStmt target_42, IfStmt target_43, IfStmt target_44, ExprStmt target_45, ExprStmt target_46, VariableAccess target_47, ExprStmt target_48, BlockStmt target_49, BlockStmt target_50, ExprStmt target_51
where
not func_0(vcollname_46, vcollnamespace_46, vcollencoding_50, void_64, target_36, target_33, func)
and not func_3(vmyself_65, target_38)
and not func_5(vmyself_65, target_38)
and not func_6(vcollname_46, vcollnamespace_46, void_64, target_33, target_40, target_32)
and not func_7(vcollname_46, vcollnamespace_46, void_64, target_33, target_41, target_42)
and not func_8(vif_not_exists_53, vquiet_54, vrel_56, void_64, target_43, target_44, target_45, target_46, func)
and not func_12(void_64, vmyself_65, target_48, target_15, target_14, func)
and func_13(func, target_13)
and func_14(vmyself_65, func, target_14)
and func_15(void_64, vmyself_65, func, target_15)
and func_16(vcollencoding_50, target_16)
and func_18(vcollname_46, vcollnamespace_46, vcollencoding_50, target_49, target_18)
and func_23(vcollname_46, target_23)
and func_24(func, target_24)
and func_25(vcollnamespace_46, target_25)
and func_28(vcollname_46, target_28)
and func_29(vcollnamespace_46, target_29)
and func_32(vcollname_46, vcollnamespace_46, vcollencoding_50, target_49, target_32)
and func_33(vcollname_46, vcollnamespace_46, vcollencoding_50, target_50, target_33)
and func_36(vcollname_46, vcollencoding_50, target_36)
and func_38(vif_not_exists_53, target_38)
and func_40(vcollname_46, vcollencoding_50, target_40)
and func_41(vcollname_46, target_41)
and func_42(vcollnamespace_46, target_42)
and func_43(vif_not_exists_53, target_43)
and func_44(vif_not_exists_53, vquiet_54, target_44)
and func_45(vrel_56, target_45)
and func_46(vrel_56, target_46)
and func_47(vif_not_exists_53, target_47)
and func_48(void_64, target_48)
and func_49(vif_not_exists_53, vquiet_54, target_49)
and func_50(vif_not_exists_53, vquiet_54, vrel_56, target_50)
and func_51(vcollencoding_50, target_51)
and vcollname_46.getType().hasName("const char *")
and vcollnamespace_46.getType().hasName("Oid")
and vcollencoding_50.getType().hasName("int32")
and vif_not_exists_53.getType().hasName("bool")
and vquiet_54.getType().hasName("bool")
and vrel_56.getType().hasName("Relation")
and void_64.getType().hasName("Oid")
and vmyself_65.getType().hasName("ObjectAddress")
and vcollname_46.getFunction() = func
and vcollnamespace_46.getFunction() = func
and vcollencoding_50.getFunction() = func
and vif_not_exists_53.getFunction() = func
and vquiet_54.getFunction() = func
and vrel_56.(LocalVariable).getFunction() = func
and void_64.(LocalVariable).getFunction() = func
and vmyself_65.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
