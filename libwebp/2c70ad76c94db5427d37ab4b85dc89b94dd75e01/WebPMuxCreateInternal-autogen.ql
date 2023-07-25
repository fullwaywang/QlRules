/**
 * @name libwebp-2c70ad76c94db5427d37ab4b85dc89b94dd75e01-WebPMuxCreateInternal
 * @id cpp/libwebp/2c70ad76c94db5427d37ab4b85dc89b94dd75e01/WebPMuxCreateInternal
 * @description libwebp-2c70ad76c94db5427d37ab4b85dc89b94dd75e01-src/mux/muxread.c-WebPMuxCreateInternal CVE-2020-36330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Variable vsize_176, ReturnStmt target_10, ExprStmt target_11, RelationalOperation target_12, VariableAccess target_0) {
		target_0.getTarget()=vsize_176
		and target_0.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="12"
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_10
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_12.getLesserOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_1(Variable vsize_176, ExprStmt target_11, RelationalOperation target_12, Literal target_1) {
		target_1.getValue()="12"
		and not target_1.getValue()="8"
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_176
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_12.getLesserOperand().(VariableAccess).getLocation())
}

*/
predicate func_2(Variable vsize_176, GotoStmt target_13, AddExpr target_2) {
		target_2.getValue()="16"
		and target_2.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vsize_176
		and target_2.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_13
}

predicate func_3(LogicalOrExpr target_14, Function func) {
	exists(GotoStmt target_3 |
		target_3.toString() = "goto ..."
		and target_3.getName() ="Err"
		and target_3.getParent().(IfStmt).getCondition()=target_14
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vriff_size_170, Variable vsize_176, BlockStmt target_15, LogicalOrExpr target_14, ExprStmt target_16) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vsize_176
		and target_4.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vriff_size_170
		and target_4.getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="8"
		and target_4.getParent().(IfStmt).getThen()=target_15
		and target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_4.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_5(Variable vriff_size_170, Variable vsize_176, RelationalOperation target_9, EqualityOperation target_17) {
	exists(AddExpr target_5 |
		target_5.getAnOperand().(VariableAccess).getTarget()=vriff_size_170
		and target_5.getAnOperand().(Literal).getValue()="8"
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_176
		and target_9.getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation())
		and target_5.getAnOperand().(VariableAccess).getLocation().isBefore(target_17.getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

/*predicate func_6(Variable vriff_size_170, Variable vsize_176, BlockStmt target_15, VariableAccess target_6) {
		target_6.getTarget()=vsize_176
		and target_6.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vriff_size_170
		and target_6.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_15
}

*/
/*predicate func_7(Variable vriff_size_170, Variable vsize_176, BlockStmt target_15, VariableAccess target_7) {
		target_7.getTarget()=vriff_size_170
		and target_7.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vsize_176
		and target_7.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_15
}

*/
predicate func_8(Variable vriff_size_170, Variable vsize_176, VariableAccess target_8) {
		target_8.getTarget()=vriff_size_170
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_176
}

predicate func_9(Variable vriff_size_170, Variable vsize_176, BlockStmt target_15, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vriff_size_170
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vsize_176
		and target_9.getParent().(IfStmt).getThen()=target_15
}

predicate func_10(ReturnStmt target_10) {
		target_10.getExpr().(Literal).getValue()="0"
}

predicate func_11(Variable vsize_176, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_176
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="size"
}

predicate func_12(Variable vsize_176, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getLesserOperand().(VariableAccess).getTarget()=vsize_176
		and target_12.getGreaterOperand() instanceof AddExpr
}

predicate func_13(GotoStmt target_13) {
		target_13.toString() = "goto ..."
		and target_13.getName() ="Err"
}

predicate func_14(Variable vriff_size_170, Variable vsize_176, LogicalOrExpr target_14) {
		target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vriff_size_170
		and target_14.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967286"
		and target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vriff_size_170
		and target_14.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_176
}

predicate func_15(Variable vriff_size_170, Variable vsize_176, BlockStmt target_15) {
		target_15.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_176
		and target_15.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vriff_size_170
}

predicate func_16(Variable vriff_size_170, Variable vsize_176, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_176
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vriff_size_170
}

predicate func_17(Variable vriff_size_170, Variable vsize_176, EqualityOperation target_17) {
		target_17.getAnOperand().(FunctionCall).getTarget().hasName("ChunkVerifyAndAssign")
		and target_17.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_176
		and target_17.getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vriff_size_170
}

from Function func, Variable vriff_size_170, Variable vsize_176, AddExpr target_2, VariableAccess target_8, RelationalOperation target_9, ReturnStmt target_10, ExprStmt target_11, RelationalOperation target_12, GotoStmt target_13, LogicalOrExpr target_14, BlockStmt target_15, ExprStmt target_16, EqualityOperation target_17
where
func_2(vsize_176, target_13, target_2)
and not func_3(target_14, func)
and not func_4(vriff_size_170, vsize_176, target_15, target_14, target_16)
and not func_5(vriff_size_170, vsize_176, target_9, target_17)
and func_8(vriff_size_170, vsize_176, target_8)
and func_9(vriff_size_170, vsize_176, target_15, target_9)
and func_10(target_10)
and func_11(vsize_176, target_11)
and func_12(vsize_176, target_12)
and func_13(target_13)
and func_14(vriff_size_170, vsize_176, target_14)
and func_15(vriff_size_170, vsize_176, target_15)
and func_16(vriff_size_170, vsize_176, target_16)
and func_17(vriff_size_170, vsize_176, target_17)
and vriff_size_170.getType().hasName("size_t")
and vsize_176.getType().hasName("size_t")
and vriff_size_170.getParentScope+() = func
and vsize_176.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
