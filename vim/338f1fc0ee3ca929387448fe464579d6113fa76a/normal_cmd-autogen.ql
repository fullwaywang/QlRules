/**
 * @name vim-338f1fc0ee3ca929387448fe464579d6113fa76a-normal_cmd
 * @id cpp/vim/338f1fc0ee3ca929387448fe464579d6113fa76a/normal-cmd
 * @description vim-338f1fc0ee3ca929387448fe464579d6113fa76a-src/normal.c-normal_cmd CVE-2022-1897
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("text_locked")
		and not target_0.getTarget().hasName("check_text_locked")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vidx_664, Parameter voap_653, Variable vnv_cmds, BlockStmt target_9, ExprStmt target_10, ExprStmt target_3) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("check_text_locked")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voap_653
		and target_1.getAnOperand() instanceof FunctionCall
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="cmd_flags"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnv_cmds
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_664
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter voap_653, LogicalAndExpr target_11, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("clearopbeep")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voap_653
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_4(Variable vidx_664, Variable vnv_cmds, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="cmd_flags"
		and target_4.getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnv_cmds
		and target_4.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_664
}

predicate func_5(Function func, FunctionCall target_5) {
		target_5.getTarget().hasName("curbuf_locked")
		and target_5.getEnclosingFunction() = func
}

predicate func_6(LogicalAndExpr target_11, Function func, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("text_locked_msg")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_6.getEnclosingFunction() = func
}

predicate func_7(LogicalAndExpr target_11, Function func, GotoStmt target_7) {
		target_7.toString() = "goto ..."
		and target_7.getName() ="normal_end"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Function func, IfStmt target_8) {
		target_8.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand() instanceof ValueFieldAccess
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_8.getThen().(GotoStmt).toString() = "goto ..."
		and target_8.getThen().(GotoStmt).getName() ="normal_end"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(BlockStmt target_9) {
		target_9.getStmt(0) instanceof ExprStmt
		and target_9.getStmt(1) instanceof ExprStmt
		and target_9.getStmt(2) instanceof GotoStmt
}

predicate func_10(Parameter voap_653, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("clearopbeep")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voap_653
}

predicate func_11(Variable vidx_664, Variable vnv_cmds, LogicalAndExpr target_11) {
		target_11.getAnOperand() instanceof FunctionCall
		and target_11.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="cmd_flags"
		and target_11.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnv_cmds
		and target_11.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_664
		and target_11.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
}

from Function func, Variable vidx_664, Parameter voap_653, Variable vnv_cmds, FunctionCall target_0, ExprStmt target_3, ValueFieldAccess target_4, FunctionCall target_5, ExprStmt target_6, GotoStmt target_7, IfStmt target_8, BlockStmt target_9, ExprStmt target_10, LogicalAndExpr target_11
where
func_0(func, target_0)
and not func_1(vidx_664, voap_653, vnv_cmds, target_9, target_10, target_3)
and func_3(voap_653, target_11, target_3)
and func_4(vidx_664, vnv_cmds, target_4)
and func_5(func, target_5)
and func_6(target_11, func, target_6)
and func_7(target_11, func, target_7)
and func_8(func, target_8)
and func_9(target_9)
and func_10(voap_653, target_10)
and func_11(vidx_664, vnv_cmds, target_11)
and vidx_664.getType().hasName("int")
and voap_653.getType().hasName("oparg_T *")
and vnv_cmds.getType() instanceof ArrayType
and vidx_664.getParentScope+() = func
and voap_653.getParentScope+() = func
and not vnv_cmds.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
