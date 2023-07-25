/**
 * @name haproxy-2e6bf0a2722866ae0128a4392fa2375bd1f03ff8-fcgi_encode_begin_request
 * @id cpp/haproxy/2e6bf0a2722866ae0128a4392fa2375bd1f03ff8/fcgi-encode-begin-request
 * @description haproxy-2e6bf0a2722866ae0128a4392fa2375bd1f03ff8-src/fcgi.c-fcgi_encode_begin_request CVE-2023-0836
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="5"
		and not target_0.getValue()="0"
		and target_0.getParent().(AssignAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignAddExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vout_87, Variable vlen_89, ExprStmt target_8) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="area"
		and target_1.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_87
		and target_1.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlen_89
		and target_1.getRValue().(Literal).getValue()="0"
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vout_87, Variable vlen_89, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="area"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_87
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlen_89
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vout_87, Variable vlen_89, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="area"
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_87
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlen_89
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_3))
}

predicate func_4(Parameter vout_87, Variable vlen_89, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="area"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_87
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlen_89
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_4))
}

predicate func_5(Parameter vout_87, Variable vlen_89, ExprStmt target_10, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="area"
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_87
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlen_89
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_5)
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Variable vlen_89, VariableAccess target_6) {
		target_6.getTarget()=vlen_89
		and target_6.getParent().(AssignAddExpr).getLValue() = target_6
		and target_6.getParent().(AssignAddExpr).getRValue() instanceof Literal
}

predicate func_7(Variable vlen_89, AssignAddExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vlen_89
		and target_7.getRValue() instanceof Literal
}

predicate func_8(Parameter vout_87, Variable vlen_89, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="area"
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_87
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlen_89
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="flags"
}

predicate func_10(Parameter vout_87, Variable vlen_89, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_87
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_89
}

from Function func, Parameter vout_87, Variable vlen_89, Literal target_0, VariableAccess target_6, AssignAddExpr target_7, ExprStmt target_8, ExprStmt target_10
where
func_0(func, target_0)
and not func_1(vout_87, vlen_89, target_8)
and not func_2(vout_87, vlen_89, func)
and not func_3(vout_87, vlen_89, func)
and not func_4(vout_87, vlen_89, func)
and not func_5(vout_87, vlen_89, target_10, func)
and func_6(vlen_89, target_6)
and func_7(vlen_89, target_7)
and func_8(vout_87, vlen_89, target_8)
and func_10(vout_87, vlen_89, target_10)
and vout_87.getType().hasName("buffer *")
and vlen_89.getType().hasName("size_t")
and vout_87.getParentScope+() = func
and vlen_89.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
