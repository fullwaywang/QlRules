/**
 * @name freerdp-b8beb55913471952f92770c90c372139d78c16c0-update_read_cache_brush_order
 * @id cpp/freerdp/b8beb55913471952f92770c90c372139d78c16c0/update-read-cache-brush-order
 * @description freerdp-b8beb55913471952f92770c90c372139d78c16c0-libfreerdp/core/orders.c-update_read_cache_brush_order CVE-2020-11096
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable viBitmapFormat_2577, ExprStmt target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("get_bmf_bpp")
		and target_0.getArgument(0).(VariableAccess).getTarget()=viBitmapFormat_2577
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(GotoStmt target_7, Function func) {
	exists(NotExpr target_1 |
		target_1.getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_1.getParent().(IfStmt).getThen()=target_7
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable viBitmapFormat_2577, GotoStmt target_7, VariableAccess target_2) {
		target_2.getTarget()=viBitmapFormat_2577
		and target_2.getParent().(GEExpr).getLesserOperand() instanceof DivExpr
		and target_2.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_3(Variable viBitmapFormat_2577, GotoStmt target_7, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=viBitmapFormat_2577
		and target_3.getLesserOperand().(DivExpr).getValue()="8"
		and target_3.getParent().(IfStmt).getThen()=target_7
}

predicate func_4(Variable viBitmapFormat_2577, Variable vBMF_BPP, ArrayExpr target_4) {
		target_4.getArrayBase().(VariableAccess).getTarget()=vBMF_BPP
		and target_4.getArrayOffset().(VariableAccess).getTarget()=viBitmapFormat_2577
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bpp"
}

predicate func_5(Variable viBitmapFormat_2577, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=viBitmapFormat_2577
		and target_5.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
}

predicate func_7(GotoStmt target_7) {
		target_7.toString() = "goto ..."
		and target_7.getName() ="fail"
}

from Function func, Variable viBitmapFormat_2577, Variable vBMF_BPP, VariableAccess target_2, RelationalOperation target_3, ArrayExpr target_4, ExprStmt target_5, GotoStmt target_7
where
not func_0(viBitmapFormat_2577, target_5)
and not func_1(target_7, func)
and func_2(viBitmapFormat_2577, target_7, target_2)
and func_3(viBitmapFormat_2577, target_7, target_3)
and func_4(viBitmapFormat_2577, vBMF_BPP, target_4)
and func_5(viBitmapFormat_2577, target_5)
and func_7(target_7)
and viBitmapFormat_2577.getType().hasName("BYTE")
and vBMF_BPP.getType() instanceof ArrayType
and viBitmapFormat_2577.getParentScope+() = func
and not vBMF_BPP.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
