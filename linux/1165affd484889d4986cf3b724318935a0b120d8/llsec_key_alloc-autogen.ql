/**
 * @name linux-1165affd484889d4986cf3b724318935a0b120d8-llsec_key_alloc
 * @id cpp/linux/1165affd484889d4986cf3b724318935a0b120d8/llsec_key_alloc
 * @description linux-1165affd484889d4986cf3b724318935a0b120d8-llsec_key_alloc 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vkey_117, Variable vi_118) {
	exists(NotExpr target_0 |
		target_0.getOperand().(FunctionCall).getTarget().hasName("IS_ERR_OR_NULL")
		and target_0.getOperand().(FunctionCall).getArgument(0) instanceof ArrayExpr
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("crypto_free_aead")
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tfm"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_117
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_118)
}

predicate func_1(Variable vkey_117, Variable vi_118) {
	exists(ArrayExpr target_1 |
		target_1.getArrayBase().(PointerFieldAccess).getTarget().getName()="tfm"
		and target_1.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_117
		and target_1.getArrayOffset().(VariableAccess).getTarget()=vi_118
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("crypto_free_aead")
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tfm"
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_117
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_118)
}

from Function func, Variable vkey_117, Variable vi_118
where
not func_0(vkey_117, vi_118)
and func_1(vkey_117, vi_118)
and vkey_117.getType().hasName("mac802154_llsec_key *")
and vi_118.getType().hasName("int")
and vkey_117.getParentScope+() = func
and vi_118.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
