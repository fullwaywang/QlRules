/**
 * @name freerdp-b8beb55913471952f92770c90c372139d78c16c0-update_write_cache_bitmap_v2_order
 * @id cpp/freerdp/b8beb55913471952f92770c90c372139d78c16c0/update-write-cache-bitmap-v2-order
 * @description freerdp-b8beb55913471952f92770c90c372139d78c16c0-libfreerdp/core/orders.c-update_write_cache_bitmap_v2_order CVE-2020-11096
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcache_bitmap_v2_2109, FunctionCall target_4, ExprStmt target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("get_bpp_bmf")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="bitmapBpp"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_v2_2109
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_4.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vcache_bitmap_v2_2109, Variable vBPP_CBR2, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="bitmapBpp"
		and target_2.getQualifier().(VariableAccess).getTarget()=vcache_bitmap_v2_2109
		and target_2.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vBPP_CBR2
}

predicate func_3(Parameter vcache_bitmap_v2_2109, Variable vBPP_CBR2, ArrayExpr target_3) {
		target_3.getArrayBase().(VariableAccess).getTarget()=vBPP_CBR2
		and target_3.getArrayOffset().(PointerFieldAccess).getTarget().getName()="bitmapBpp"
		and target_3.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_v2_2109
		and target_3.getParent().(AssignExpr).getRValue() = target_3
}

predicate func_4(Parameter vcache_bitmap_v2_2109, FunctionCall target_4) {
		target_4.getTarget().hasName("update_approximate_cache_bitmap_v2_order")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vcache_bitmap_v2_2109
}

predicate func_5(Parameter vcache_bitmap_v2_2109, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cacheId"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_v2_2109
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="3"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_v2_2109
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="7"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="65408"
}

from Function func, Parameter vcache_bitmap_v2_2109, Variable vBPP_CBR2, PointerFieldAccess target_2, ArrayExpr target_3, FunctionCall target_4, ExprStmt target_5
where
not func_0(vcache_bitmap_v2_2109, target_4, target_5)
and not func_1(func)
and func_2(vcache_bitmap_v2_2109, vBPP_CBR2, target_2)
and func_3(vcache_bitmap_v2_2109, vBPP_CBR2, target_3)
and func_4(vcache_bitmap_v2_2109, target_4)
and func_5(vcache_bitmap_v2_2109, target_5)
and vcache_bitmap_v2_2109.getType().hasName("CACHE_BITMAP_V2_ORDER *")
and vBPP_CBR2.getType() instanceof ArrayType
and vcache_bitmap_v2_2109.getParentScope+() = func
and not vBPP_CBR2.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
