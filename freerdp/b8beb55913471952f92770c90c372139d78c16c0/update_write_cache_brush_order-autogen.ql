/**
 * @name freerdp-b8beb55913471952f92770c90c372139d78c16c0-update_write_cache_brush_order
 * @id cpp/freerdp/b8beb55913471952f92770c90c372139d78c16c0/update-write-cache-brush-order
 * @description freerdp-b8beb55913471952f92770c90c372139d78c16c0-libfreerdp/core/orders.c-update_write_cache_brush_order CVE-2020-11096
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcache_brush_2660, FunctionCall target_4, ExprStmt target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("get_bpp_bmf")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="bpp"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_brush_2660
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_4.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_1))
}

predicate func_2(Variable vBPP_BMF, Parameter vcache_brush_2660, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="bpp"
		and target_2.getQualifier().(VariableAccess).getTarget()=vcache_brush_2660
		and target_2.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vBPP_BMF
}

predicate func_3(Variable vBPP_BMF, Parameter vcache_brush_2660, ArrayExpr target_3) {
		target_3.getArrayBase().(VariableAccess).getTarget()=vBPP_BMF
		and target_3.getArrayOffset().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_3.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_brush_2660
		and target_3.getParent().(AssignExpr).getRValue() = target_3
}

predicate func_4(Parameter vcache_brush_2660, FunctionCall target_4) {
		target_4.getTarget().hasName("update_approximate_cache_brush_order")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vcache_brush_2660
}

predicate func_5(Parameter vcache_brush_2660, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("Stream_Write_UINT8")
		and target_5.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="index"
		and target_5.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_brush_2660
}

from Function func, Variable vBPP_BMF, Parameter vcache_brush_2660, PointerFieldAccess target_2, ArrayExpr target_3, FunctionCall target_4, ExprStmt target_5
where
not func_0(vcache_brush_2660, target_4, target_5)
and not func_1(func)
and func_2(vBPP_BMF, vcache_brush_2660, target_2)
and func_3(vBPP_BMF, vcache_brush_2660, target_3)
and func_4(vcache_brush_2660, target_4)
and func_5(vcache_brush_2660, target_5)
and vBPP_BMF.getType() instanceof ArrayType
and vcache_brush_2660.getType().hasName("const CACHE_BRUSH_ORDER *")
and not vBPP_BMF.getParentScope+() = func
and vcache_brush_2660.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
