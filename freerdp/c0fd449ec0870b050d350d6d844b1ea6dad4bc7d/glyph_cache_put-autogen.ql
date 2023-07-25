/**
 * @name freerdp-c0fd449ec0870b050d350d6d844b1ea6dad4bc7d-glyph_cache_put
 * @id cpp/freerdp/c0fd449ec0870b050d350d6d844b1ea6dad4bc7d/glyph-cache-put
 * @description freerdp-c0fd449ec0870b050d350d6d844b1ea6dad4bc7d-libfreerdp/cache/glyph.c-glyph_cache_put CVE-2020-11098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vindex_572, BlockStmt target_4, ExprStmt target_5) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vindex_572
		and target_0.getLesserOperand() instanceof ValueFieldAccess
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vid_572, Parameter vglyphCache_572, ValueFieldAccess target_1) {
		target_1.getTarget().getName()="number"
		and target_1.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="glyphCache"
		and target_1.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vglyphCache_572
		and target_1.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vid_572
}

*/
predicate func_2(Parameter vid_572, Parameter vindex_572, Parameter vglyphCache_572, BlockStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vindex_572
		and target_2.getParent().(GTExpr).getLesserOperand().(ValueFieldAccess).getTarget().getName()="number"
		and target_2.getParent().(GTExpr).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="glyphCache"
		and target_2.getParent().(GTExpr).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vglyphCache_572
		and target_2.getParent().(GTExpr).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vid_572
		and target_2.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Parameter vindex_572, BlockStmt target_4, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vindex_572
		and target_3.getLesserOperand() instanceof ValueFieldAccess
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("WLog_Get")
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("WLog_IsLevelActive")
		and target_4.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_5(Parameter vid_572, Parameter vindex_572, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_5.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_5.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="invalid glyph cache index: %u in cache id: %u"
		and target_5.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vindex_572
		and target_5.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vid_572
}

from Function func, Parameter vid_572, Parameter vindex_572, Parameter vglyphCache_572, VariableAccess target_2, RelationalOperation target_3, BlockStmt target_4, ExprStmt target_5
where
not func_0(vindex_572, target_4, target_5)
and func_2(vid_572, vindex_572, vglyphCache_572, target_4, target_2)
and func_3(vindex_572, target_4, target_3)
and func_4(target_4)
and func_5(vid_572, vindex_572, target_5)
and vid_572.getType().hasName("UINT32")
and vindex_572.getType().hasName("UINT32")
and vglyphCache_572.getType().hasName("rdpGlyphCache *")
and vid_572.getParentScope+() = func
and vindex_572.getParentScope+() = func
and vglyphCache_572.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
