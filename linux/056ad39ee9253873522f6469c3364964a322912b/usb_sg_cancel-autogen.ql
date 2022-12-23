/**
 * @name linux-056ad39ee9253873522f6469c3364964a322912b-usb_sg_cancel
 * @id cpp/linux/056ad39ee9253873522f6469c3364964a322912b/usb-sg-cancel
 * @description linux-056ad39ee9253873522f6469c3364964a322912b-usb_sg_cancel 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vio_586, Variable vflags_588) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof PointerFieldAccess
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_586
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_unlock_irqrestore")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_586
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vflags_588
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).toString() = "return ...")
}

predicate func_1(Parameter vio_586, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_1.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_586
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vio_586, Variable vflags_588, Function func) {
	exists(DoStmt target_2 |
		target_2.getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof LongType
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof LongType
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned long")
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned long")
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vflags_588
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_raw_spin_lock_irqsave")
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("spinlock_check")
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_586
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_2))
}

predicate func_10(Parameter vio_586, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_10.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_586
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_10))
}

predicate func_11(Parameter vio_586, Function func) {
	exists(IfStmt target_11 |
		target_11.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_11.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_586
		and target_11.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("complete")
		and target_11.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="complete"
		and target_11.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_586
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_11))
}

predicate func_12(Parameter vio_586, Variable vflags_588, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("spin_unlock_irqrestore")
		and target_12.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_12.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_586
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vflags_588
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_12))
}

predicate func_13(Parameter vio_586, Variable vflags_588) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="status"
		and target_13.getQualifier().(VariableAccess).getTarget()=vio_586
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_unlock_irqrestore")
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vio_586
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vflags_588
		and target_13.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).toString() = "return ...")
}

predicate func_14(Parameter vio_586) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="lock"
		and target_14.getQualifier().(VariableAccess).getTarget()=vio_586)
}

predicate func_15(Parameter vio_586) {
	exists(PointerFieldAccess target_15 |
		target_15.getTarget().getName()="status"
		and target_15.getQualifier().(VariableAccess).getTarget()=vio_586)
}

predicate func_16(Parameter vio_586) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="dev"
		and target_16.getQualifier().(VariableAccess).getTarget()=vio_586)
}

from Function func, Parameter vio_586, Variable vflags_588
where
not func_0(vio_586, vflags_588)
and not func_1(vio_586, func)
and not func_2(vio_586, vflags_588, func)
and not func_10(vio_586, func)
and not func_11(vio_586, func)
and not func_12(vio_586, vflags_588, func)
and func_13(vio_586, vflags_588)
and vio_586.getType().hasName("usb_sg_request *")
and func_14(vio_586)
and func_15(vio_586)
and func_16(vio_586)
and vflags_588.getType().hasName("unsigned long")
and vio_586.getParentScope+() = func
and vflags_588.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
