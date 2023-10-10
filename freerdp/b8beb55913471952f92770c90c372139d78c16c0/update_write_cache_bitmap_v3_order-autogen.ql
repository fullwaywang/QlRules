/**
 * @name freerdp-b8beb55913471952f92770c90c372139d78c16c0-update_write_cache_bitmap_v3_order
 * @id cpp/freerdp/b8beb55913471952f92770c90c372139d78c16c0/update-write-cache-bitmap-v3-order
 * @description freerdp-b8beb55913471952f92770c90c372139d78c16c0-libfreerdp/core/orders.c-update_write_cache_bitmap_v3_order CVE-2020-11096
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcache_bitmap_v3_2242, ExprStmt target_4, ExprStmt target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("get_bpp_bmf")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="bpp"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_v3_2242
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_1))
}

predicate func_2(Variable vBPP_CBR23, Parameter vcache_bitmap_v3_2242, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="bpp"
		and target_2.getQualifier().(VariableAccess).getTarget()=vcache_bitmap_v3_2242
		and target_2.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vBPP_CBR23
}

predicate func_3(Variable vBPP_CBR23, Parameter vcache_bitmap_v3_2242, ArrayExpr target_3) {
		target_3.getArrayBase().(VariableAccess).getTarget()=vBPP_CBR23
		and target_3.getArrayOffset().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_3.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_v3_2242
		and target_3.getParent().(AssignExpr).getRValue() = target_3
}

predicate func_4(Parameter vcache_bitmap_v3_2242, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="bitmapData"
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_v3_2242
}

predicate func_5(Parameter vcache_bitmap_v3_2242, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cacheId"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_v3_2242
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="3"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="7"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="65408"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_5.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="120"
}

from Function func, Variable vBPP_CBR23, Parameter vcache_bitmap_v3_2242, PointerFieldAccess target_2, ArrayExpr target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vcache_bitmap_v3_2242, target_4, target_5)
and not func_1(func)
and func_2(vBPP_CBR23, vcache_bitmap_v3_2242, target_2)
and func_3(vBPP_CBR23, vcache_bitmap_v3_2242, target_3)
and func_4(vcache_bitmap_v3_2242, target_4)
and func_5(vcache_bitmap_v3_2242, target_5)
and vBPP_CBR23.getType() instanceof ArrayType
and vcache_bitmap_v3_2242.getType().hasName("CACHE_BITMAP_V3_ORDER *")
and not vBPP_CBR23.getParentScope+() = func
and vcache_bitmap_v3_2242.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
