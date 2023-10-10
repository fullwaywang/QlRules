/**
 * @name libtiff-a95b799f65064e4ba2e2dfc206808f86faf93e85-TIFFFetchNormalTag
 * @id cpp/libtiff/a95b799f65064e4ba2e2dfc206808f86faf93e85/TIFFFetchNormalTag
 * @description libtiff-a95b799f65064e4ba2e2dfc206808f86faf93e85-libtiff/tif_dirread.c-TIFFFetchNormalTag CVE-2022-0908
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdp_5035, RelationalOperation target_2, AddExpr target_3, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_5035
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdata_5060, Variable vo_5082, Parameter vdp_5035, RelationalOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemcpy")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vo_5082
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_5060
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_5035
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vdp_5035, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_2.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_5035
}

predicate func_3(Parameter vdp_5035, AddExpr target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_5035
		and target_3.getAnOperand().(Literal).getValue()="1"
}

from Function func, Variable vdata_5060, Variable vo_5082, Parameter vdp_5035, ExprStmt target_1, RelationalOperation target_2, AddExpr target_3
where
not func_0(vdp_5035, target_2, target_3, target_1)
and func_1(vdata_5060, vo_5082, vdp_5035, target_2, target_1)
and func_2(vdp_5035, target_2)
and func_3(vdp_5035, target_3)
and vdata_5060.getType().hasName("uint8_t *")
and vo_5082.getType().hasName("uint8_t *")
and vdp_5035.getType().hasName("TIFFDirEntry *")
and vdata_5060.(LocalVariable).getFunction() = func
and vo_5082.(LocalVariable).getFunction() = func
and vdp_5035.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
