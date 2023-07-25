/**
 * @name ghostscript-937ccd17ac65935633b2ebc06cb7089b91e17e6b-gx_ttfReader__Read
 * @id cpp/ghostscript/937ccd17ac65935633b2ebc06cb7089b91e17e6b/gx-ttfReader--Read
 * @description ghostscript-937ccd17ac65935633b2ebc06cb7089b91e17e6b-base/gxttfb.c-gx_ttfReader__Read CVE-2017-9727
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vr_76, ExprStmt target_2, ValueFieldAccess target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="pos"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_76
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="bits"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="glyph_data"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_76
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vn_74, Variable vr_76, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="bits"
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="glyph_data"
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_76
		and target_1.getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="pos"
		and target_1.getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_76
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vn_74
}

predicate func_2(Variable vr_76, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="error"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_76
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_3(Variable vr_76, ValueFieldAccess target_3) {
		target_3.getTarget().getName()="bits"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="glyph_data"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_76
}

from Function func, Parameter vn_74, Variable vr_76, RelationalOperation target_1, ExprStmt target_2, ValueFieldAccess target_3
where
not func_0(vr_76, target_2, target_3)
and func_1(vn_74, vr_76, target_1)
and func_2(vr_76, target_2)
and func_3(vr_76, target_3)
and vn_74.getType().hasName("int")
and vr_76.getType().hasName("gx_ttfReader *")
and vn_74.getFunction() = func
and vr_76.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
