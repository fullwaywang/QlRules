/**
 * @name postgresql-5919bb5a5989cda232ac3d1f8b9d90f337be2077-CollationCreate
 * @id cpp/postgresql/5919bb5a5989cda232ac3d1f8b9d90f337be2077/CollationCreate
 * @description postgresql-5919bb5a5989cda232ac3d1f8b9d90f337be2077-src/backend/catalog/pg_collation.c-CollationCreate CVE-2022-2625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(UnaryMinusExpr).getParent().(NEExpr).getAnOperand() instanceof UnaryMinusExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vcollname_47, Variable void_64, ConditionalExpr target_35, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=void_64
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetSysCacheOid")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof EnumConstantAccess
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof BitwiseAndExpr
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3) instanceof BitwiseAndExpr
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_1)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_35.getThen().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_3(Variable vmyself_65, VariableAccess target_37) {
	exists(DoStmt target_3 |
		target_3.getCondition().(Literal).getValue()="0"
		and target_3.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_3.getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_3.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_3.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_3.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37)
}

/*predicate func_4(Variable vmyself_65, LogicalOrExpr target_32) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_32)
}

*/
predicate func_5(Variable vmyself_65, VariableAccess target_37) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmyself_65
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37)
}

predicate func_6(Parameter vcollname_47, Variable void_64, LogicalOrExpr target_32, ConditionalExpr target_39) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=void_64
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetSysCacheOid")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof EnumConstantAccess
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof BitwiseAndExpr
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3) instanceof BitwiseAndExpr
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4) instanceof Literal
		and target_6.getParent().(IfStmt).getCondition()=target_32
		and target_39.getThen().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_7(Parameter vcollname_47, Variable void_64, LogicalOrExpr target_32, FunctionCall target_40) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=void_64
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetSysCacheOid")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof EnumConstantAccess
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof BitwiseAndExpr
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3) instanceof BitwiseAndExpr
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4) instanceof Literal
		and target_7.getParent().(IfStmt).getCondition()=target_32
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_40.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_8(Parameter vif_not_exists_53, Parameter vquiet_54, Variable vrel_56, Variable void_64, IfStmt target_41, IfStmt target_42, ExprStmt target_43, ExprStmt target_44, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=void_64
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vquiet_54
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("relation_close")
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_56
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(VariableAccess).getTarget()=vif_not_exists_53
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("relation_close")
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(DoStmt).getCondition() instanceof Literal
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_8)
		and target_41.getCondition().(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(VariableAccess).getLocation())
		and target_42.getCondition().(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getLocation())
		and target_43.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_44.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_9(Variable void_64, Variable vmyself_65, VariableAccess target_45) {
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
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_45)
}

*/
/*predicate func_10(Variable vmyself_65, VariableAccess target_45) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmyself_65
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_45)
}

*/
predicate func_12(Variable void_64, Variable vmyself_65, ExprStmt target_46, ExprStmt target_20, ExprStmt target_19, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=void_64
		and (func.getEntryPoint().(BlockStmt).getStmt(35)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(35).getFollowingStmt()=target_12)
		and target_46.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_13(Parameter vcollname_47, Parameter vcollnamespace_47, Parameter vcollencoding_50, BlockStmt target_47, BitwiseAndExpr target_13) {
		target_13.getLeftOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_13.getRightOperand().(Literal).getValue()="4294967295"
		and target_13.getParent().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_13.getParent().(FunctionCall).getArgument(3).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vcollnamespace_47
		and target_13.getParent().(FunctionCall).getArgument(3).(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4294967295"
		and target_13.getParent().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_13.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_47
}

/*predicate func_14(Parameter vcollname_47, Parameter vcollnamespace_47, Parameter vcollencoding_50, BlockStmt target_47, BitwiseAndExpr target_14) {
		target_14.getLeftOperand().(VariableAccess).getTarget()=vcollnamespace_47
		and target_14.getRightOperand().(Literal).getValue()="4294967295"
		and target_14.getParent().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_14.getParent().(FunctionCall).getArgument(2).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_14.getParent().(FunctionCall).getArgument(2).(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4294967295"
		and target_14.getParent().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_14.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_47
}

*/
predicate func_15(Function func, BitwiseAndExpr target_15) {
		target_15.getLeftOperand().(FunctionCall).getTarget().hasName("GetDatabaseEncoding")
		and target_15.getRightOperand().(Literal).getValue()="4294967295"
		and target_15.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_15.getEnclosingFunction() = func
}

predicate func_16(Parameter vcollnamespace_47, BitwiseAndExpr target_16) {
		target_16.getLeftOperand().(VariableAccess).getTarget()=vcollnamespace_47
		and target_16.getRightOperand().(Literal).getValue()="4294967295"
		and target_16.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_17(Function func, BitwiseAndExpr target_17) {
		target_17.getValue()="4294967295"
		and target_17.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_17.getEnclosingFunction() = func
}

predicate func_18(Parameter vcollnamespace_47, BitwiseAndExpr target_18) {
		target_18.getLeftOperand().(VariableAccess).getTarget()=vcollnamespace_47
		and target_18.getRightOperand().(Literal).getValue()="4294967295"
		and target_18.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_19(Variable vmyself_65, Function func, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_19.getExpr().(AssignExpr).getRValue().(Literal).getValue()="3456"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19
}

predicate func_20(Variable void_64, Variable vmyself_65, Function func, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_20.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_65
		and target_20.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=void_64
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_20
}

predicate func_21(Parameter vcollencoding_50, EqualityOperation target_21) {
		target_21.getAnOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_21.getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

/*predicate func_23(Parameter vcollname_47, Parameter vcollnamespace_47, Parameter vcollencoding_50, BlockStmt target_47, VariableAccess target_23) {
		target_23.getTarget()=vcollname_47
		and target_23.getParent().(FunctionCall).getArgument(2).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_23.getParent().(FunctionCall).getArgument(2).(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4294967295"
		and target_23.getParent().(FunctionCall).getArgument(3).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vcollnamespace_47
		and target_23.getParent().(FunctionCall).getArgument(3).(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4294967295"
		and target_23.getParent().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_23.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_47
}

*/
predicate func_26(Parameter vcollname_47, VariableAccess target_26) {
		target_26.getTarget()=vcollname_47
		and target_26.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_29(Parameter vcollname_47, VariableAccess target_29) {
		target_29.getTarget()=vcollname_47
		and target_29.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_31(Parameter vcollname_47, BlockStmt target_47, FunctionCall target_31) {
		target_31.getTarget().hasName("SearchSysCacheExists")
		and target_31.getArgument(0) instanceof EnumConstantAccess
		and target_31.getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_31.getArgument(2) instanceof BitwiseAndExpr
		and target_31.getArgument(3) instanceof BitwiseAndExpr
		and target_31.getArgument(4) instanceof Literal
		and target_31.getParent().(IfStmt).getThen()=target_47
}

predicate func_32(Parameter vcollname_47, Parameter vcollencoding_50, BlockStmt target_48, LogicalOrExpr target_32) {
		target_32.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("SearchSysCacheExists")
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0) instanceof EnumConstantAccess
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2) instanceof BitwiseAndExpr
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3) instanceof BitwiseAndExpr
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(4) instanceof Literal
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("SearchSysCacheExists")
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0) instanceof EnumConstantAccess
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2) instanceof BitwiseAndExpr
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(3) instanceof BitwiseAndExpr
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(4) instanceof Literal
		and target_32.getParent().(IfStmt).getThen()=target_48
}

/*predicate func_33(Parameter vcollencoding_50, LogicalOrExpr target_32, ExprStmt target_49, VariableAccess target_33) {
		target_33.getTarget()=vcollencoding_50
		and target_32.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_33.getLocation())
		and target_33.getLocation().isBefore(target_49.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_34(Function func, UnaryMinusExpr target_34) {
		target_34.getValue()="-1"
		and target_34.getEnclosingFunction() = func
}

*/
predicate func_35(Parameter vcollname_47, Parameter vcollencoding_50, ConditionalExpr target_35) {
		target_35.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_35.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_35.getThen().(FunctionCall).getTarget().hasName("errmsg")
		and target_35.getThen().(FunctionCall).getArgument(0).(StringLiteral).getValue()="collation \"%s\" already exists, skipping"
		and target_35.getThen().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_35.getElse().(FunctionCall).getTarget().hasName("errmsg")
		and target_35.getElse().(FunctionCall).getArgument(0).(StringLiteral).getValue()="collation \"%s\" for encoding \"%s\" already exists, skipping"
		and target_35.getElse().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_35.getElse().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("pg_encoding_to_char")
		and target_35.getElse().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcollencoding_50
}

predicate func_37(Parameter vif_not_exists_53, VariableAccess target_37) {
		target_37.getTarget()=vif_not_exists_53
}

predicate func_39(Parameter vcollname_47, Parameter vcollencoding_50, ConditionalExpr target_39) {
		target_39.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_39.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_39.getThen().(FunctionCall).getTarget().hasName("errmsg")
		and target_39.getThen().(FunctionCall).getArgument(0).(StringLiteral).getValue()="collation \"%s\" already exists"
		and target_39.getThen().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_39.getElse().(FunctionCall).getTarget().hasName("errmsg")
		and target_39.getElse().(FunctionCall).getArgument(0).(StringLiteral).getValue()="collation \"%s\" for encoding \"%s\" already exists"
		and target_39.getElse().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcollname_47
		and target_39.getElse().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("pg_encoding_to_char")
		and target_39.getElse().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcollencoding_50
}

predicate func_40(Parameter vcollname_47, FunctionCall target_40) {
		target_40.getTarget().hasName("errmsg")
		and target_40.getArgument(0).(StringLiteral).getValue()="collation \"%s\" already exists, skipping"
		and target_40.getArgument(1).(VariableAccess).getTarget()=vcollname_47
}

predicate func_41(Parameter vif_not_exists_53, IfStmt target_41) {
		target_41.getCondition().(VariableAccess).getTarget()=vif_not_exists_53
		and target_41.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_41.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_41.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_41.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_41.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_41.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_41.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_41.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_41.getElse().(DoStmt).getCondition() instanceof Literal
		and target_41.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_41.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_41.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_41.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_41.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_41.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_41.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_41.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
}

predicate func_42(Parameter vif_not_exists_53, Parameter vquiet_54, IfStmt target_42) {
		target_42.getCondition().(VariableAccess).getTarget()=vquiet_54
		and target_42.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_42.getElse().(IfStmt).getCondition().(VariableAccess).getTarget()=vif_not_exists_53
		and target_42.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_42.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_42.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_42.getElse().(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and target_42.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_42.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_42.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_42.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_42.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_42.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_42.getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
}

predicate func_43(Variable vrel_56, ExprStmt target_43) {
		target_43.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrel_56
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("heap_open")
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="3456"
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="6"
}

predicate func_44(Variable vrel_56, ExprStmt target_44) {
		target_44.getExpr().(FunctionCall).getTarget().hasName("relation_close")
		and target_44.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_56
		and target_44.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_45(Parameter vif_not_exists_53, VariableAccess target_45) {
		target_45.getTarget()=vif_not_exists_53
}

predicate func_46(Variable vrel_56, Variable void_64, ExprStmt target_46) {
		target_46.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=void_64
		and target_46.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CatalogTupleInsert")
		and target_46.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_56
		and target_46.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("HeapTuple")
}

predicate func_47(Parameter vif_not_exists_53, Parameter vquiet_54, BlockStmt target_47) {
		target_47.getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vquiet_54
		and target_47.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_47.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(VariableAccess).getTarget()=vif_not_exists_53
		and target_47.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_47.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_47.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and target_47.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
}

predicate func_48(Parameter vif_not_exists_53, Parameter vquiet_54, Variable vrel_56, BlockStmt target_48) {
		target_48.getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vquiet_54
		and target_48.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("relation_close")
		and target_48.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_56
		and target_48.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_48.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_48.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(VariableAccess).getTarget()=vif_not_exists_53
		and target_48.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("relation_close")
		and target_48.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_56
		and target_48.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_48.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_48.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_48.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and target_48.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
}

predicate func_49(Parameter vcollencoding_50, ExprStmt target_49) {
		target_49.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("Datum[8]")
		and target_49.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getValue()="4"
		and target_49.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vcollencoding_50
		and target_49.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4294967295"
}

from Function func, Parameter vcollname_47, Parameter vcollnamespace_47, Parameter vcollencoding_50, Parameter vif_not_exists_53, Parameter vquiet_54, Variable vrel_56, Variable void_64, Variable vmyself_65, Literal target_0, BitwiseAndExpr target_13, BitwiseAndExpr target_15, BitwiseAndExpr target_16, BitwiseAndExpr target_17, BitwiseAndExpr target_18, ExprStmt target_19, ExprStmt target_20, EqualityOperation target_21, VariableAccess target_26, VariableAccess target_29, FunctionCall target_31, LogicalOrExpr target_32, ConditionalExpr target_35, VariableAccess target_37, ConditionalExpr target_39, FunctionCall target_40, IfStmt target_41, IfStmt target_42, ExprStmt target_43, ExprStmt target_44, VariableAccess target_45, ExprStmt target_46, BlockStmt target_47, BlockStmt target_48, ExprStmt target_49
where
func_0(func, target_0)
and not func_1(vcollname_47, void_64, target_35, func)
and not func_3(vmyself_65, target_37)
and not func_5(vmyself_65, target_37)
and not func_6(vcollname_47, void_64, target_32, target_39)
and not func_7(vcollname_47, void_64, target_32, target_40)
and not func_8(vif_not_exists_53, vquiet_54, vrel_56, void_64, target_41, target_42, target_43, target_44, func)
and not func_12(void_64, vmyself_65, target_46, target_20, target_19, func)
and func_13(vcollname_47, vcollnamespace_47, vcollencoding_50, target_47, target_13)
and func_15(func, target_15)
and func_16(vcollnamespace_47, target_16)
and func_17(func, target_17)
and func_18(vcollnamespace_47, target_18)
and func_19(vmyself_65, func, target_19)
and func_20(void_64, vmyself_65, func, target_20)
and func_21(vcollencoding_50, target_21)
and func_26(vcollname_47, target_26)
and func_29(vcollname_47, target_29)
and func_31(vcollname_47, target_47, target_31)
and func_32(vcollname_47, vcollencoding_50, target_48, target_32)
and func_35(vcollname_47, vcollencoding_50, target_35)
and func_37(vif_not_exists_53, target_37)
and func_39(vcollname_47, vcollencoding_50, target_39)
and func_40(vcollname_47, target_40)
and func_41(vif_not_exists_53, target_41)
and func_42(vif_not_exists_53, vquiet_54, target_42)
and func_43(vrel_56, target_43)
and func_44(vrel_56, target_44)
and func_45(vif_not_exists_53, target_45)
and func_46(vrel_56, void_64, target_46)
and func_47(vif_not_exists_53, vquiet_54, target_47)
and func_48(vif_not_exists_53, vquiet_54, vrel_56, target_48)
and func_49(vcollencoding_50, target_49)
and vcollname_47.getType().hasName("const char *")
and vcollnamespace_47.getType().hasName("Oid")
and vcollencoding_50.getType().hasName("int32")
and vif_not_exists_53.getType().hasName("bool")
and vquiet_54.getType().hasName("bool")
and vrel_56.getType().hasName("Relation")
and void_64.getType().hasName("Oid")
and vmyself_65.getType().hasName("ObjectAddress")
and vcollname_47.getFunction() = func
and vcollnamespace_47.getFunction() = func
and vcollencoding_50.getFunction() = func
and vif_not_exists_53.getFunction() = func
and vquiet_54.getFunction() = func
and vrel_56.(LocalVariable).getFunction() = func
and void_64.(LocalVariable).getFunction() = func
and vmyself_65.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
