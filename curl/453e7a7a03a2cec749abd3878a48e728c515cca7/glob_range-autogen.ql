/**
 * @name curl-453e7a7a03a2cec749abd3878a48e728c515cca7-glob_range
 * @id cpp/curl/453e7a7a03a2cec749abd3878a48e728c515cca7/glob-range
 * @description curl-453e7a7a03a2cec749abd3878a48e728c515cca7-src/tool_urlglob.c-glob_range CVE-2017-1000101
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vendp_244, LogicalOrExpr target_5, ExprStmt target_6) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vendp_244
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getCondition()=target_5
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpattern_185, Variable vstep_n_243, Variable vendp_244, LogicalOrExpr target_5, ExprStmt target_7, LogicalAndExpr target_9) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof EqualityOperation
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpattern_185
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vendp_244
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstep_n_243
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strtoul")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpattern_185
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vendp_244
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="10"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vendp_244
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getElse() instanceof ExprStmt
		and target_1.getParent().(IfStmt).getCondition()=target_5
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vstep_n_243, LogicalOrExpr target_5, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstep_n_243
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_2.getParent().(IfStmt).getCondition()=target_5
}

predicate func_3(Variable vendp_244, BlockStmt target_10, PointerDereferenceExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vendp_244
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="58"
		and target_3.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_10
}

/*predicate func_4(Variable vendp_244, BlockStmt target_10, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vendp_244
		and target_4.getAnOperand().(CharLiteral).getValue()="58"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_4.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_10
}

*/
predicate func_5(BlockStmt target_10, Function func, LogicalOrExpr target_5) {
		target_5.getAnOperand() instanceof PointerDereferenceExpr
		and target_5.getAnOperand() instanceof EqualityOperation
		and target_5.getParent().(IfStmt).getThen()=target_10
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Variable vpattern_185, Variable vendp_244, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpattern_185
		and target_6.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vendp_244
		and target_6.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_7(Variable vpattern_185, Variable vendp_244, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned long")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strtoul")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpattern_185
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vendp_244
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="10"
}

predicate func_9(Variable vendp_244, LogicalAndExpr target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vendp_244
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vendp_244
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="93"
}

predicate func_10(Variable vpattern_185, Variable vendp_244, BlockStmt target_10) {
		target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpattern_185
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vendp_244
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_10.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_10.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vpattern_185, Variable vstep_n_243, Variable vendp_244, ExprStmt target_2, PointerDereferenceExpr target_3, LogicalOrExpr target_5, ExprStmt target_6, ExprStmt target_7, LogicalAndExpr target_9, BlockStmt target_10
where
not func_0(vendp_244, target_5, target_6)
and not func_1(vpattern_185, vstep_n_243, vendp_244, target_5, target_7, target_9)
and func_2(vstep_n_243, target_5, target_2)
and func_3(vendp_244, target_10, target_3)
and func_5(target_10, func, target_5)
and func_6(vpattern_185, vendp_244, target_6)
and func_7(vpattern_185, vendp_244, target_7)
and func_9(vendp_244, target_9)
and func_10(vpattern_185, vendp_244, target_10)
and vpattern_185.getType().hasName("char *")
and vstep_n_243.getType().hasName("unsigned long")
and vendp_244.getType().hasName("char *")
and vpattern_185.(LocalVariable).getFunction() = func
and vstep_n_243.(LocalVariable).getFunction() = func
and vendp_244.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
