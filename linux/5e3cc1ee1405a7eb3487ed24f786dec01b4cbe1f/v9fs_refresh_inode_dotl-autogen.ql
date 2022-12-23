/**
 * @name linux-5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f-v9fs_refresh_inode_dotl
 * @id cpp/linux/5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f/v9fs_refresh_inode_dotl
 * @description linux-5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f-v9fs_refresh_inode_dotl 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(VariableDeclarationEntry target_0 |
		target_0.getType() instanceof IntType
		and target_0.getDeclaration().getParentScope+() = func)
}

predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_1.getRValue().(ConditionalExpr).getCondition() instanceof LogicalOrExpr
		and target_1.getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_1.getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Variable vv9ses_933) {
	exists(LogicalOrExpr target_3 |
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cache"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv9ses_933
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cache"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv9ses_933
		and target_3.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_4(Parameter vinode_929, Variable vst_932) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("v9fs_stat2inode_dotl")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vst_932
		and target_4.getArgument(1).(VariableAccess).getTarget()=vinode_929)
}

predicate func_5(Function func) {
	exists(VariableDeclarationEntry target_5 |
		target_5.getType() instanceof CTypedefType
		and target_5.getDeclaration().getParentScope+() = func)
}

predicate func_6(Parameter vinode_929) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("spin_lock")
		and target_6.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_lock"
		and target_6.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_929)
}

predicate func_7(Parameter vinode_929, Variable vi_size_931) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vi_size_931
		and target_7.getRValue().(PointerFieldAccess).getTarget().getName()="i_size"
		and target_7.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_929)
}

predicate func_8(Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_9(Parameter vinode_929, Variable vi_size_931, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition() instanceof LogicalOrExpr
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="i_size"
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_929
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vi_size_931
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

predicate func_10(Parameter vinode_929, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_lock"
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_929
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

from Function func, Parameter vinode_929, Variable vi_size_931, Variable vst_932, Variable vv9ses_933
where
not func_0(func)
and not func_1(func)
and func_3(vv9ses_933)
and func_4(vinode_929, vst_932)
and func_5(func)
and func_6(vinode_929)
and func_7(vinode_929, vi_size_931)
and func_8(func)
and func_9(vinode_929, vi_size_931, func)
and func_10(vinode_929, func)
and vinode_929.getType().hasName("inode *")
and vst_932.getType().hasName("p9_stat_dotl *")
and vv9ses_933.getType().hasName("v9fs_session_info *")
and vinode_929.getParentScope+() = func
and vi_size_931.getParentScope+() = func
and vst_932.getParentScope+() = func
and vv9ses_933.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
