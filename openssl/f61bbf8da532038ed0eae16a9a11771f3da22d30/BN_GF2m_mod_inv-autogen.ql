/**
 * @name openssl-f61bbf8da532038ed0eae16a9a11771f3da22d30-BN_GF2m_mod_inv
 * @id cpp/openssl/f61bbf8da532038ed0eae16a9a11771f3da22d30/BN-GF2m-mod-inv
 * @description openssl-f61bbf8da532038ed0eae16a9a11771f3da22d30-crypto/bn/bn_gf2m.c-BN_GF2m_mod_inv CVE-2015-1788
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vudp_700, LogicalAndExpr target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vudp_700
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(GotoStmt).getName() ="err"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7)
}

predicate func_1(LogicalAndExpr target_7, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof EqualityOperation
		and target_1.getThen().(BreakStmt).toString() = "break;"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_1.getEnclosingFunction() = func)
}

/*predicate func_5(Variable vubits_697, Variable vudp_700, BreakStmt target_8, RelationalOperation target_5) {
		 (target_5 instanceof GEExpr or target_5 instanceof LEExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vubits_697
		and target_5.getGreaterOperand().(Literal).getValue()="64"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vudp_700
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_8
}

*/
/*predicate func_6(Variable vubits_697, Variable vudp_700, BreakStmt target_8, EqualityOperation target_6) {
		target_6.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vudp_700
		and target_6.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getAnOperand().(Literal).getValue()="1"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vubits_697
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="64"
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_8
}

*/
predicate func_7(BreakStmt target_8, Function func, LogicalAndExpr target_7) {
		target_7.getAnOperand() instanceof RelationalOperation
		and target_7.getAnOperand() instanceof EqualityOperation
		and target_7.getParent().(IfStmt).getThen()=target_8
		and target_7.getEnclosingFunction() = func
}

predicate func_8(BreakStmt target_8) {
		target_8.toString() = "break;"
}

from Function func, Variable vubits_697, Variable vudp_700, LogicalAndExpr target_7, BreakStmt target_8
where
not func_0(vudp_700, target_7)
and not func_1(target_7, func)
and func_7(target_8, func, target_7)
and func_8(target_8)
and vubits_697.getType().hasName("int")
and vudp_700.getType().hasName("unsigned long *")
and vubits_697.getParentScope+() = func
and vudp_700.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
