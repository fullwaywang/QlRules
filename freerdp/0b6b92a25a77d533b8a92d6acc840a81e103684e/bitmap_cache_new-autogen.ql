/**
 * @name freerdp-0b6b92a25a77d533b8a92d6acc840a81e103684e-bitmap_cache_new
 * @id cpp/freerdp/0b6b92a25a77d533b8a92d6acc840a81e103684e/bitmap-cache-new
 * @description freerdp-0b6b92a25a77d533b8a92d6acc840a81e103684e-libfreerdp/cache/bitmap.c-bitmap_cache_new CVE-2020-11525
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbitmapCache_275, FunctionCall target_0) {
		target_0.getTarget().hasName("free")
		and not target_0.getTarget().hasName("bitmap_cache_free")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbitmapCache_275
}

predicate func_2(Variable vi_274, Variable vbitmapCache_275, Function func, IfStmt target_2) {
		target_2.getCondition().(PointerFieldAccess).getTarget().getName()="cells"
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbitmapCache_275
		and target_2.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_274
		and target_2.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_274
		and target_2.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="maxCells"
		and target_2.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbitmapCache_275
		and target_2.getThen().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_274
		and target_2.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_2.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="entries"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

/*predicate func_3(Variable vi_274, Variable vbitmapCache_275, PointerFieldAccess target_4, ForStmt target_3) {
		target_3.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_274
		and target_3.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_274
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="maxCells"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbitmapCache_275
		and target_3.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_274
		and target_3.getStmt().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_3.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="entries"
		and target_3.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cells"
		and target_3.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbitmapCache_275
		and target_3.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_274
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

*/
predicate func_4(Variable vbitmapCache_275, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="cells"
		and target_4.getQualifier().(VariableAccess).getTarget()=vbitmapCache_275
}

from Function func, Variable vi_274, Variable vbitmapCache_275, FunctionCall target_0, IfStmt target_2, PointerFieldAccess target_4
where
func_0(vbitmapCache_275, target_0)
and func_2(vi_274, vbitmapCache_275, func, target_2)
and func_4(vbitmapCache_275, target_4)
and vi_274.getType().hasName("int")
and vbitmapCache_275.getType().hasName("rdpBitmapCache *")
and vi_274.getParentScope+() = func
and vbitmapCache_275.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
