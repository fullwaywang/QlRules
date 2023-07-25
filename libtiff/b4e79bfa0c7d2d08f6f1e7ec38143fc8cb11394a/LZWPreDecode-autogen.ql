/**
 * @name libtiff-b4e79bfa0c7d2d08f6f1e7ec38143fc8cb11394a-LZWPreDecode
 * @id cpp/libtiff/b4e79bfa0c7d2d08f6f1e7ec38143fc8cb11394a/LZWPreDecode
 * @description libtiff-b4e79bfa0c7d2d08f6f1e7ec38143fc8cb11394a-libtiff/tif_lzw.c-LZWPreDecode CVE-2022-1622
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsp_241, ExprStmt target_1, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="read_error"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_241
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsp_241, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dec_maxcodep"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_241
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="dec_codetab"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_241
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="dec_nbitsmask"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_241
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vsp_241, ExprStmt target_1
where
not func_0(vsp_241, target_1, func)
and func_1(vsp_241, target_1)
and vsp_241.getType().hasName("LZWCodecState *")
and vsp_241.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
