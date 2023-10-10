/**
 * @name postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-closePGconn
 * @id cpp/postgresql/d1c6a14bacfa5fe7690e2c71b1626dbc87a57355/closePGconn
 * @description postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-src/interfaces/libpq/fe-connect.c-closePGconn CVE-2018-10915
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vprev_3610, FunctionCall target_0) {
		target_0.getTarget().hasName("free")
		and not target_0.getTarget().hasName("pqDropServerData")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vprev_3610
}

predicate func_1(Parameter vconn_3582, ExprStmt target_20, ExprStmt target_11) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="xactStatus"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3582
		and target_20.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vconn_3582, VariableAccess target_2) {
		target_2.getTarget()=vconn_3582
}

predicate func_3(Parameter vconn_3582, VariableAccess target_3) {
		target_3.getTarget()=vconn_3582
}

predicate func_4(Function func, DeclStmt target_4) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Function func, DeclStmt target_5) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vnotify_3584, Parameter vconn_3582, AssignExpr target_6) {
		target_6.getLValue().(VariableAccess).getTarget()=vnotify_3584
		and target_6.getRValue().(PointerFieldAccess).getTarget().getName()="notifyHead"
		and target_6.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3582
}

predicate func_7(Variable vnotify_3584, Function func, WhileStmt target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnotify_3584
		and target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnotify_3584
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnotify_3584
		and target_7.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

/*predicate func_9(Variable vnotify_3584, AssignExpr target_9) {
		target_9.getLValue().(VariableAccess).getTarget()=vnotify_3584
		and target_9.getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_9.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnotify_3584
}

*/
/*predicate func_10(Function func, ExprStmt target_10) {
		target_10.getExpr() instanceof FunctionCall
		and target_10.getEnclosingFunction() = func
}

*/
predicate func_11(Parameter vconn_3582, Function func, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="notifyHead"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3582
		and target_11.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="notifyTail"
		and target_11.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3582
		and target_11.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

predicate func_12(Variable vpstatus_3585, Parameter vconn_3582, Function func, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpstatus_3585
		and target_12.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="pstatus"
		and target_12.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3582
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Variable vpstatus_3585, Variable vprev_3619, Function func, WhileStmt target_13) {
		target_13.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpstatus_3585
		and target_13.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_13.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpstatus_3585
		and target_13.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_13.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpstatus_3585
		and target_13.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_13.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprev_3619
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

/*predicate func_15(Variable vpstatus_3585, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpstatus_3585
		and target_15.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_15.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpstatus_3585
}

*/
/*predicate func_16(Variable vprev_3619, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprev_3619
}

*/
predicate func_17(Parameter vconn_3582, Function func, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pstatus"
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3582
		and target_17.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17
}

predicate func_18(Parameter vconn_3582, Function func, IfStmt target_18) {
		target_18.getCondition().(PointerFieldAccess).getTarget().getName()="lobjfuncs"
		and target_18.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3582
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="lobjfuncs"
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3582
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18
}

predicate func_19(Parameter vconn_3582, Function func, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lobjfuncs"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3582
		and target_19.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19
}

predicate func_20(Parameter vconn_3582, ExprStmt target_20) {
		target_20.getExpr().(FunctionCall).getTarget().hasName("release_all_addrinfo")
		and target_20.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_3582
}

from Function func, Variable vnotify_3584, Variable vpstatus_3585, Variable vprev_3610, Variable vprev_3619, Parameter vconn_3582, FunctionCall target_0, VariableAccess target_2, VariableAccess target_3, DeclStmt target_4, DeclStmt target_5, AssignExpr target_6, WhileStmt target_7, ExprStmt target_11, ExprStmt target_12, WhileStmt target_13, ExprStmt target_17, IfStmt target_18, ExprStmt target_19, ExprStmt target_20
where
func_0(vprev_3610, target_0)
and not func_1(vconn_3582, target_20, target_11)
and func_2(vconn_3582, target_2)
and func_3(vconn_3582, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(vnotify_3584, vconn_3582, target_6)
and func_7(vnotify_3584, func, target_7)
and func_11(vconn_3582, func, target_11)
and func_12(vpstatus_3585, vconn_3582, func, target_12)
and func_13(vpstatus_3585, vprev_3619, func, target_13)
and func_17(vconn_3582, func, target_17)
and func_18(vconn_3582, func, target_18)
and func_19(vconn_3582, func, target_19)
and func_20(vconn_3582, target_20)
and vnotify_3584.getType().hasName("PGnotify *")
and vpstatus_3585.getType().hasName("pgParameterStatus *")
and vprev_3610.getType().hasName("PGnotify *")
and vprev_3619.getType().hasName("pgParameterStatus *")
and vconn_3582.getType().hasName("PGconn *")
and vnotify_3584.(LocalVariable).getFunction() = func
and vpstatus_3585.(LocalVariable).getFunction() = func
and vprev_3610.(LocalVariable).getFunction() = func
and vprev_3619.(LocalVariable).getFunction() = func
and vconn_3582.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
