/**
 * @name linux-19b61392c5a852b4e8a0bf35aecb969983c5932d-dw_spi_transfer_one
 * @id cpp/linux/19b61392c5a852b4e8a0bf35aecb969983c5932d/dw-spi-transfer-one
 * @description linux-19b61392c5a852b4e8a0bf35aecb969983c5932d-dw_spi_transfer_one 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof LongType
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_0)
}

predicate func_1(Variable vdws_277, Function func) {
	exists(DoStmt target_1 |
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof LongType
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof LongType
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned long")
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned long")
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned long")
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_raw_spin_lock_irqsave")
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("spinlock_check")
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf_lock"
		and target_1.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdws_277
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1))
}

predicate func_9(Variable vdws_277, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("spin_unlock_irqrestore")
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf_lock"
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdws_277
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("unsigned long")
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_9))
}

predicate func_10(Variable vdws_277) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="dma_mapped"
		and target_10.getQualifier().(VariableAccess).getTarget()=vdws_277)
}

predicate func_11(Variable vdws_277) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="len"
		and target_11.getQualifier().(VariableAccess).getTarget()=vdws_277)
}

from Function func, Variable vdws_277
where
not func_0(func)
and not func_1(vdws_277, func)
and not func_9(vdws_277, func)
and vdws_277.getType().hasName("dw_spi *")
and func_10(vdws_277)
and func_11(vdws_277)
and vdws_277.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
