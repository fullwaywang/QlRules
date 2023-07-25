/**
 * @name libtpms-2f30d620d3c053f20d38b54bf76ac0907821d263-TPMS_NV_PUBLIC_Unmarshal
 * @id cpp/libtpms/2f30d620d3c053f20d38b54bf76ac0907821d263/TPMS-NV-PUBLIC-Unmarshal
 * @description libtpms-2f30d620d3c053f20d38b54bf76ac0907821d263-src/tpm2/Unmarshal.c-TPMS_NV_PUBLIC_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_4220, RelationalOperation target_1) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dataSize"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_4220
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1)
}

predicate func_1(Parameter vtarget_4220, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dataSize"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtarget_4220
		and target_1.getLesserOperand().(Literal).getValue()="2048"
}

from Function func, Parameter vtarget_4220, RelationalOperation target_1
where
not func_0(vtarget_4220, target_1)
and func_1(vtarget_4220, target_1)
and vtarget_4220.getType().hasName("TPMS_NV_PUBLIC *")
and vtarget_4220.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
