/**
 * @name postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-connectDBComplete
 * @id cpp/postgresql/d1c6a14bacfa5fe7690e2c71b1626dbc87a57355/connectDBComplete
 * @description postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-src/interfaces/libpq/fe-connect.c-connectDBComplete CVE-2018-10915
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_1840, ExprStmt target_16) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="try_next_addr"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_0.getRValue() instanceof Literal
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vconn_1840, RelationalOperation target_9) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="try_next_host"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_1.getRValue() instanceof Literal
		and target_9.getGreaterOperand().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vtimeout_1844, BlockStmt target_18, ExprStmt target_19, ExprStmt target_20) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vtimeout_1844
		and target_2.getLesserOperand() instanceof Literal
		and target_2.getParent().(IfStmt).getThen()=target_18
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vconn_1840, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="status"
		and target_3.getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_3.getParent().(AssignExpr).getLValue() = target_3
		and target_3.getParent().(AssignExpr).getRValue() instanceof EnumConstantAccess
}

predicate func_4(Parameter vconn_1840, VariableAccess target_4) {
		target_4.getTarget()=vconn_1840
}

predicate func_5(Parameter vconn_1840, VariableAccess target_5) {
		target_5.getTarget()=vconn_1840
}

predicate func_9(Parameter vconn_1840, BlockStmt target_18, RelationalOperation target_9) {
		 (target_9 instanceof GEExpr or target_9 instanceof LEExpr)
		and target_9.getGreaterOperand().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="whichhost"
		and target_9.getGreaterOperand().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_9.getLesserOperand().(PointerFieldAccess).getTarget().getName()="nconnhost"
		and target_9.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_9.getParent().(IfStmt).getThen()=target_18
}

predicate func_10(Parameter vconn_1840, AssignExpr target_10) {
		target_10.getLValue().(PointerFieldAccess).getTarget().getName()="whichhost"
		and target_10.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_10.getRValue() instanceof Literal
}

predicate func_11(Parameter vconn_1840, ExprStmt target_13, AssignExpr target_11) {
		target_11.getLValue().(PointerFieldAccess).getTarget().getName()="status"
		and target_11.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_11.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_12(RelationalOperation target_9, Function func, ReturnStmt target_12) {
		target_12.getExpr() instanceof Literal
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_12.getEnclosingFunction() = func
}

predicate func_13(Parameter vconn_1840, EqualityOperation target_22, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("pqDropConnection")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1840
		and target_13.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

predicate func_14(Parameter vconn_1840, EqualityOperation target_22, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="addr_cur"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_14.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="addrlist"
		and target_14.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="connhost"
		and target_14.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_14.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="whichhost"
		and target_14.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

predicate func_15(Variable vfinish_time_1843, Variable vtimeout_1844, Parameter vconn_1840, EqualityOperation target_22, IfStmt target_15) {
		target_15.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="connect_timeout"
		and target_15.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
		and target_15.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfinish_time_1843
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("time")
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtimeout_1844
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

predicate func_16(Parameter vconn_1840, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1840
}

predicate func_18(BlockStmt target_18) {
		target_18.getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
		and target_18.getStmt(1).(ExprStmt).getExpr() instanceof AssignExpr
		and target_18.getStmt(2) instanceof ReturnStmt
}

predicate func_19(Variable vfinish_time_1843, Variable vtimeout_1844, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfinish_time_1843
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("time")
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtimeout_1844
}

predicate func_20(Variable vfinish_time_1843, Variable vtimeout_1844, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfinish_time_1843
		and target_20.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("time")
		and target_20.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_20.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtimeout_1844
}

predicate func_22(EqualityOperation target_22) {
		target_22.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_22.getAnOperand().(Literal).getValue()="1"
}

from Function func, Variable vfinish_time_1843, Variable vtimeout_1844, Parameter vconn_1840, PointerFieldAccess target_3, VariableAccess target_4, VariableAccess target_5, RelationalOperation target_9, AssignExpr target_10, AssignExpr target_11, ReturnStmt target_12, ExprStmt target_13, ExprStmt target_14, IfStmt target_15, ExprStmt target_16, BlockStmt target_18, ExprStmt target_19, ExprStmt target_20, EqualityOperation target_22
where
not func_0(vconn_1840, target_16)
and not func_1(vconn_1840, target_9)
and not func_2(vtimeout_1844, target_18, target_19, target_20)
and func_3(vconn_1840, target_3)
and func_4(vconn_1840, target_4)
and func_5(vconn_1840, target_5)
and func_9(vconn_1840, target_18, target_9)
and func_10(vconn_1840, target_10)
and func_11(vconn_1840, target_13, target_11)
and func_12(target_9, func, target_12)
and func_13(vconn_1840, target_22, target_13)
and func_14(vconn_1840, target_22, target_14)
and func_15(vfinish_time_1843, vtimeout_1844, vconn_1840, target_22, target_15)
and func_16(vconn_1840, target_16)
and func_18(target_18)
and func_19(vfinish_time_1843, vtimeout_1844, target_19)
and func_20(vfinish_time_1843, vtimeout_1844, target_20)
and func_22(target_22)
and vfinish_time_1843.getType().hasName("time_t")
and vtimeout_1844.getType().hasName("int")
and vconn_1840.getType().hasName("PGconn *")
and vfinish_time_1843.(LocalVariable).getFunction() = func
and vtimeout_1844.(LocalVariable).getFunction() = func
and vconn_1840.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
