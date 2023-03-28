/**
 * @name redis-9fdcc15962f9ff4baebe6fdd947816f43f730d50-cliRefreshPrompt
 * @id cpp/redis/9fdcc15962f9ff4baebe6fdd947816f43f730d50/cliRefreshPrompt
 * @description redis-9fdcc15962f9ff4baebe6fdd947816f43f730d50-cliRefreshPrompt CVE-2018-12326
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofExprOperator target_0) {
		target_0.getValue()="128"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="[%d]"
		and not target_1.getValue()="[%i]"
		and target_1.getEnclosingFunction() = func
}

predicate func_3(EqualityOperation target_27, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("sds")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sdscatfmt")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sds")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof ValueFieldAccess
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
		and target_3.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(VariableAccess).getType().hasName("sds")
		and target_6.getRValue().(FunctionCall).getTarget().hasName("sdscatlen")
		and target_6.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sds")
		and target_6.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("char[256]")
		and target_6.getRValue().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_6.getRValue().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[256]")
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getType().hasName("sds")
		and target_7.getRValue().(FunctionCall).getTarget().hasName("sdscatfmt")
		and target_7.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sds")
		and target_7.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="[%i]"
		and target_7.getRValue().(FunctionCall).getArgument(2) instanceof ValueFieldAccess
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(AssignExpr target_8 |
		target_8.getLValue().(VariableAccess).getType().hasName("sds")
		and target_8.getRValue().(FunctionCall).getTarget().hasName("sdscatlen")
		and target_8.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sds")
		and target_8.getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_9.getExpr().(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and target_9.getExpr().(FunctionCall).getArgument(1) instanceof SizeofExprOperator
		and target_9.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_9.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("sds")
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_9))
}

predicate func_12(Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("sdsfree")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sds")
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_12))
}

predicate func_13(Variable vconfig, ValueFieldAccess target_13) {
		target_13.getTarget().getName()="prompt"
		and target_13.getQualifier().(VariableAccess).getTarget()=vconfig
}

predicate func_14(Function func, SizeofExprOperator target_14) {
		target_14.getValue()="128"
		and target_14.getEnclosingFunction() = func
}

predicate func_15(Variable vconfig, ValueFieldAccess target_15) {
		target_15.getTarget().getName()="hostsocket"
		and target_15.getQualifier().(VariableAccess).getTarget()=vconfig
}

predicate func_16(Variable vconfig, ValueFieldAccess target_16) {
		target_16.getTarget().getName()="dbnum"
		and target_16.getQualifier().(VariableAccess).getTarget()=vconfig
}

predicate func_20(Variable vlen_155, AssignExpr target_20) {
		target_20.getLValue().(VariableAccess).getTarget()=vlen_155
		and target_20.getRValue().(FunctionCall).getTarget().hasName("snprintf")
		and target_20.getRValue().(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and target_20.getRValue().(FunctionCall).getArgument(1) instanceof SizeofExprOperator
		and target_20.getRValue().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_20.getRValue().(FunctionCall).getArgument(3) instanceof ValueFieldAccess
}

predicate func_21(Variable vlen_155, Variable vconfig, AssignExpr target_21) {
		target_21.getLValue().(VariableAccess).getTarget()=vlen_155
		and target_21.getRValue().(FunctionCall).getTarget().hasName("anetFormatAddr")
		and target_21.getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="prompt"
		and target_21.getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig
		and target_21.getRValue().(FunctionCall).getArgument(1) instanceof SizeofExprOperator
		and target_21.getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="hostip"
		and target_21.getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig
		and target_21.getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="hostport"
		and target_21.getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig
}

/*predicate func_22(Variable vconfig, ValueFieldAccess target_15, ValueFieldAccess target_22) {
		target_22.getTarget().getName()="prompt"
		and target_22.getQualifier().(VariableAccess).getTarget()=vconfig
		and target_15.getQualifier().(VariableAccess).getLocation().isBefore(target_22.getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_23(Variable vconfig, ValueFieldAccess target_28, VariableAccess target_23) {
		target_23.getTarget()=vconfig
		and target_23.getLocation().isBefore(target_28.getQualifier().(VariableAccess).getLocation())
}

predicate func_24(Variable vlen_155, Variable vconfig, AssignAddExpr target_24) {
		target_24.getLValue().(VariableAccess).getTarget()=vlen_155
		and target_24.getRValue().(FunctionCall).getTarget().hasName("snprintf")
		and target_24.getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prompt"
		and target_24.getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig
		and target_24.getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_155
		and target_24.getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="128"
		and target_24.getRValue().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_155
		and target_24.getRValue().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_24.getRValue().(FunctionCall).getArgument(3) instanceof ValueFieldAccess
}

/*predicate func_25(Variable vlen_155, Variable vconfig, SubExpr target_29, ValueFieldAccess target_16, PointerArithmeticOperation target_25) {
		target_25.getAnOperand().(ValueFieldAccess).getTarget().getName()="prompt"
		and target_25.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig
		and target_25.getAnOperand().(VariableAccess).getTarget()=vlen_155
		and target_25.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_25.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="128"
		and target_25.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_155
		and target_25.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_29.getRightOperand().(VariableAccess).getLocation().isBefore(target_25.getAnOperand().(VariableAccess).getLocation())
		and target_16.getQualifier().(VariableAccess).getLocation().isBefore(target_25.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
/*predicate func_26(Variable vlen_155, Variable vconfig, ValueFieldAccess target_16, SubExpr target_26) {
		target_26.getLeftOperand().(SizeofExprOperator).getValue()="128"
		and target_26.getRightOperand().(VariableAccess).getTarget()=vlen_155
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prompt"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_155
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_16.getQualifier().(VariableAccess).getLocation().isBefore(target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_27(Variable vconfig, EqualityOperation target_27) {
		target_27.getAnOperand().(ValueFieldAccess).getTarget().getName()="hostsocket"
		and target_27.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig
		and target_27.getAnOperand().(Literal).getValue()="0"
}

predicate func_28(Variable vconfig, ValueFieldAccess target_28) {
		target_28.getTarget().getName()="hostip"
		and target_28.getQualifier().(VariableAccess).getTarget()=vconfig
}

predicate func_29(Variable vlen_155, SubExpr target_29) {
		target_29.getLeftOperand() instanceof SizeofExprOperator
		and target_29.getRightOperand().(VariableAccess).getTarget()=vlen_155
}

from Function func, Variable vlen_155, Variable vconfig, SizeofExprOperator target_0, StringLiteral target_1, ValueFieldAccess target_13, SizeofExprOperator target_14, ValueFieldAccess target_15, ValueFieldAccess target_16, AssignExpr target_20, AssignExpr target_21, VariableAccess target_23, AssignAddExpr target_24, EqualityOperation target_27, ValueFieldAccess target_28, SubExpr target_29
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_3(target_27, func)
and not func_6(func)
and not func_7(func)
and not func_8(func)
and not func_9(func)
and not func_12(func)
and func_13(vconfig, target_13)
and func_14(func, target_14)
and func_15(vconfig, target_15)
and func_16(vconfig, target_16)
and func_20(vlen_155, target_20)
and func_21(vlen_155, vconfig, target_21)
and func_23(vconfig, target_28, target_23)
and func_24(vlen_155, vconfig, target_24)
and func_27(vconfig, target_27)
and func_28(vconfig, target_28)
and func_29(vlen_155, target_29)
and vlen_155.getType().hasName("int")
and vconfig.getType().hasName("config")
and vlen_155.getParentScope+() = func
and not vconfig.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
