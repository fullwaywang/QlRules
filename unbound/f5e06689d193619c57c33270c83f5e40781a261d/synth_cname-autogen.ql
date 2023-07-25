/**
 * @name unbound-f5e06689d193619c57c33270c83f5e40781a261d-synth_cname
 * @id cpp/unbound/f5e06689d193619c57c33270c83f5e40781a261d/synth-cname
 * @description unbound-f5e06689d193619c57c33270c83f5e40781a261d-iterator/iter_scrub.c-synth_cname CVE-2019-25036
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vqnamelen_212, Parameter vdname_rrset_212, NotExpr target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vqnamelen_212
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dname_len"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdname_rrset_212
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_2.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vqnamelen_212, ExprStmt target_3, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vqnamelen_212
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdname_rrset_212, NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("parse_get_cname_target")
		and target_2.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdname_rrset_212
}

predicate func_3(Parameter vqnamelen_212, Parameter vdname_rrset_212, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vqnamelen_212
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="dname_len"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdname_rrset_212
}

from Function func, Parameter vqnamelen_212, Parameter vdname_rrset_212, NotExpr target_2, ExprStmt target_3
where
not func_0(vqnamelen_212, vdname_rrset_212, target_2, target_3, func)
and not func_1(vqnamelen_212, target_3, func)
and func_2(vdname_rrset_212, target_2)
and func_3(vqnamelen_212, vdname_rrset_212, target_3)
and vqnamelen_212.getType().hasName("size_t")
and vdname_rrset_212.getType().hasName("rrset_parse *")
and vqnamelen_212.getParentScope+() = func
and vdname_rrset_212.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
