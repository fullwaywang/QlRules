/**
 * @name freerdp-0b6b92a25a77d533b8a92d6acc840a81e103684e-bitmap_cache_get
 * @id cpp/freerdp/0b6b92a25a77d533b8a92d6acc840a81e103684e/bitmap-cache-get
 * @description freerdp-0b6b92a25a77d533b8a92d6acc840a81e103684e-libfreerdp/cache/bitmap.c-bitmap_cache_get CVE-2020-11525
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vid_213, Parameter vbitmapCache_213, BlockStmt target_4, ExprStmt target_5, ArrayExpr target_6) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vid_213
		and target_0.getLesserOperand().(PointerFieldAccess).getTarget().getName()="maxCells"
		and target_0.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbitmapCache_213
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation())
		and target_0.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vid_213, Parameter vbitmapCache_213, BlockStmt target_4, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="maxCells"
		and target_1.getQualifier().(VariableAccess).getTarget()=vbitmapCache_213
		and target_1.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vid_213
		and target_1.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_4
}

*/
/*predicate func_2(Parameter vid_213, Parameter vbitmapCache_213, BlockStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vid_213
		and target_2.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="maxCells"
		and target_2.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbitmapCache_213
		and target_2.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_4
}

*/
predicate func_3(Parameter vid_213, Parameter vbitmapCache_213, BlockStmt target_4, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vid_213
		and target_3.getLesserOperand().(PointerFieldAccess).getTarget().getName()="maxCells"
		and target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbitmapCache_213
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("WLog_Get")
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("WLog_IsLevelActive")
		and target_4.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_5(Parameter vid_213, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_5.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_5.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="get invalid bitmap cell id: %u"
		and target_5.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vid_213
}

predicate func_6(Parameter vid_213, Parameter vbitmapCache_213, ArrayExpr target_6) {
		target_6.getArrayBase().(PointerFieldAccess).getTarget().getName()="cells"
		and target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbitmapCache_213
		and target_6.getArrayOffset().(VariableAccess).getTarget()=vid_213
}

from Function func, Parameter vid_213, Parameter vbitmapCache_213, RelationalOperation target_3, BlockStmt target_4, ExprStmt target_5, ArrayExpr target_6
where
not func_0(vid_213, vbitmapCache_213, target_4, target_5, target_6)
and func_3(vid_213, vbitmapCache_213, target_4, target_3)
and func_4(target_4)
and func_5(vid_213, target_5)
and func_6(vid_213, vbitmapCache_213, target_6)
and vid_213.getType().hasName("UINT32")
and vbitmapCache_213.getType().hasName("rdpBitmapCache *")
and vid_213.getParentScope+() = func
and vbitmapCache_213.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
