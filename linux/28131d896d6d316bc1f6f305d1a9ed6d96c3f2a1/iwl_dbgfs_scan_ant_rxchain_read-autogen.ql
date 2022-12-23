/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dbgfs_scan_ant_rxchain_read
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-dbgfs-scan-ant-rxchain-read
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dbgfs_scan_ant_rxchain_read CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmvm_1052) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="scan_rx_ant"
		and target_0.getQualifier().(VariableAccess).getTarget()=vmvm_1052
		and target_0.getParent().(BitwiseAndExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_0.getParent().(BitwiseAndExpr).getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_1(Variable vpos_1053, Variable vbuf_1054) {
	exists(PointerArithmeticOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vbuf_1054
		and target_1.getAnOperand().(VariableAccess).getTarget()=vpos_1053
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue() instanceof FunctionCall)
}

predicate func_2(Variable vpos_1053, Variable vbufsz_1055) {
	exists(SubExpr target_2 |
		target_2.getLeftOperand().(VariableAccess).getTarget()=vbufsz_1055
		and target_2.getRightOperand().(VariableAccess).getTarget()=vpos_1053
		and target_2.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue() instanceof FunctionCall)
}

predicate func_3(Variable vpos_1053, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(BitwiseAndExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_3.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="4"
		and target_3.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_3.getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vpos_1053
		and target_3.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("scnprintf")
		and target_3.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_3.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1) instanceof SubExpr
		and target_3.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="C"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

from Function func, Variable vmvm_1052, Variable vpos_1053, Variable vbuf_1054, Variable vbufsz_1055
where
func_0(vmvm_1052)
and func_1(vpos_1053, vbuf_1054)
and func_2(vpos_1053, vbufsz_1055)
and func_3(vpos_1053, func)
and vmvm_1052.getType().hasName("iwl_mvm *")
and vpos_1053.getType().hasName("int")
and vbuf_1054.getType().hasName("char[32]")
and vbufsz_1055.getType().hasName("const size_t")
and vmvm_1052.getParentScope+() = func
and vpos_1053.getParentScope+() = func
and vbuf_1054.getParentScope+() = func
and vbufsz_1055.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
