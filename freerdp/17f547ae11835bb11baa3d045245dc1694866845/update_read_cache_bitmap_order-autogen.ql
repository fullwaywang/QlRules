/**
 * @name freerdp-17f547ae11835bb11baa3d045245dc1694866845-update_read_cache_bitmap_order
 * @id cpp/freerdp/17f547ae11835bb11baa3d045245dc1694866845/update-read-cache-bitmap-order
 * @description freerdp-17f547ae11835bb11baa3d045245dc1694866845-libfreerdp/core/orders.c-update_read_cache_bitmap_order CVE-2020-11521
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcache_bitmap_1863, ExprStmt target_1, RelationalOperation target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bitmapLength"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_1863
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcache_bitmap_1863, ExprStmt target_1) {
		target_1.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bitmapLength"
		and target_1.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_1863
		and target_1.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="8"
}

predicate func_2(Variable vcache_bitmap_1863, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_2.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="bitmapLength"
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_bitmap_1863
}

from Function func, Variable vcache_bitmap_1863, ExprStmt target_1, RelationalOperation target_2
where
not func_0(vcache_bitmap_1863, target_1, target_2, func)
and func_1(vcache_bitmap_1863, target_1)
and func_2(vcache_bitmap_1863, target_2)
and vcache_bitmap_1863.getType().hasName("CACHE_BITMAP_ORDER *")
and vcache_bitmap_1863.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
