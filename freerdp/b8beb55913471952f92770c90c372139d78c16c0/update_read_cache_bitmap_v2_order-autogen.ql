/**
 * @name freerdp-b8beb55913471952f92770c90c372139d78c16c0-update_read_cache_bitmap_v2_order
 * @id cpp/freerdp/b8beb55913471952f92770c90c372139d78c16c0/update-read-cache-bitmap-v2-order
 * @description freerdp-b8beb55913471952f92770c90c372139d78c16c0-libfreerdp/core/orders.c-update_read_cache_bitmap_v2_order CVE-2020-11096
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbitsPerPixelId_2019, ExprStmt target_4) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("get_cbr2_bpp")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbitsPerPixelId_2019
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1))
}

predicate func_2(Variable vbitsPerPixelId_2019, Variable vCBR2_BPP, VariableAccess target_2) {
		target_2.getTarget()=vbitsPerPixelId_2019
		and target_2.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vCBR2_BPP
}

predicate func_3(Variable vbitsPerPixelId_2019, Variable vCBR2_BPP, ArrayExpr target_3) {
		target_3.getArrayBase().(VariableAccess).getTarget()=vCBR2_BPP
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vbitsPerPixelId_2019
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bitmapBpp"
}

predicate func_4(Variable vbitsPerPixelId_2019, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbitsPerPixelId_2019
		and target_4.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="120"
		and target_4.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
}

from Function func, Variable vbitsPerPixelId_2019, Variable vCBR2_BPP, VariableAccess target_2, ArrayExpr target_3, ExprStmt target_4
where
not func_0(vbitsPerPixelId_2019, target_4)
and not func_1(func)
and func_2(vbitsPerPixelId_2019, vCBR2_BPP, target_2)
and func_3(vbitsPerPixelId_2019, vCBR2_BPP, target_3)
and func_4(vbitsPerPixelId_2019, target_4)
and vbitsPerPixelId_2019.getType().hasName("BYTE")
and vCBR2_BPP.getType() instanceof ArrayType
and vbitsPerPixelId_2019.getParentScope+() = func
and not vCBR2_BPP.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
