/**
 * @name linux-dd504589577d8e8e70f51f997ad487a4cb6c026f-skcipher_accept_parent
 * @id cpp/linux/dd504589577d8e8e70f51f997ad487a4cb6c026f/skcipher_accept_parent
 * @description linux-dd504589577d8e8e70f51f997ad487a4cb6c026f-skcipher_accept_parent 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vprivate_791) {
	exists(VariableDeclarationEntry target_0 |
		target_0.getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vprivate_791)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="skcipher"
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("skcipher_tfm *")
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_1)
}

predicate func_2(Variable vctx_793, Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vctx_793
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("crypto_skcipher_reqsize")
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("crypto_skcipher *")
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_2)
}

predicate func_4(Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="has_key"
		and target_4.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("skcipher_tfm *")
		and target_4.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-126"
		and target_4.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="126"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_4))
}

from Function func, Parameter vprivate_791, Variable vctx_793
where
not func_0(vprivate_791)
and not func_1(func)
and not func_2(vctx_793, func)
and not func_4(func)
and vprivate_791.getType().hasName("void *")
and vctx_793.getType().hasName("skcipher_ctx *")
and vprivate_791.getParentScope+() = func
and vctx_793.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
