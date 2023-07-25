/**
 * @name htslib-dcd4b7304941a8832fba2d0fc4c1e716e7a4e72c-vcf_parse_format
 * @id cpp/htslib/dcd4b7304941a8832fba2d0fc4c1e716e7a4e72c/vcf-parse-format
 * @description htslib-dcd4b7304941a8832fba2d0fc4c1e716e7a4e72c-vcf.c-vcf_parse_format CVE-2020-36403
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmem_2216, BlockStmt target_2, ExprStmt target_3, RelationalOperation target_4) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="l"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmem_2216
		and target_0.getAnOperand() instanceof MulExpr
		and target_0.getParent().(GTExpr).getGreaterOperand() instanceof MulExpr
		and target_0.getParent().(GTExpr).getLesserOperand().(Literal).getValue()="2147483647"
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vf_2340, Parameter vv_2206, BlockStmt target_2, MulExpr target_1) {
		target_1.getLeftOperand().(PointerFieldAccess).getTarget().getName()="n_sample"
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_2206
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_2340
		and target_1.getParent().(GTExpr).getLesserOperand().(Literal).getValue()="2147483647"
		and target_1.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vv_2206, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("hts_log")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Excessive memory required by FORMAT fields at %s:%ld"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("bcf_seqname_safe")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vv_2206
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="pos"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_2206
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_3(Variable vmem_2216, Variable vf_2340, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="offset"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_2340
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmem_2216
}

predicate func_4(Variable vmem_2216, Variable vf_2340, Parameter vv_2206, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(FunctionCall).getTarget().hasName("ks_resize")
		and target_4.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmem_2216
		and target_4.getLesserOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="l"
		and target_4.getLesserOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmem_2216
		and target_4.getLesserOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="n_sample"
		and target_4.getLesserOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_2206
		and target_4.getLesserOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getLesserOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_2340
		and target_4.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vmem_2216, Variable vf_2340, Parameter vv_2206, MulExpr target_1, BlockStmt target_2, ExprStmt target_3, RelationalOperation target_4
where
not func_0(vmem_2216, target_2, target_3, target_4)
and func_1(vf_2340, vv_2206, target_2, target_1)
and func_2(vv_2206, target_2)
and func_3(vmem_2216, vf_2340, target_3)
and func_4(vmem_2216, vf_2340, vv_2206, target_4)
and vmem_2216.getType().hasName("kstring_t *")
and vf_2340.getType().hasName("fmt_aux_t *")
and vv_2206.getType().hasName("bcf1_t *")
and vmem_2216.getParentScope+() = func
and vf_2340.getParentScope+() = func
and vv_2206.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
