/**
 * @name linux-51b2ee7d006a736a9126e8111d1f24e4fd0afaa6-compose_entry_fh
 * @id cpp/linux/51b2ee7d006a736a9126e8111d1f24e4fd0afaa6/compose-entry-fh
 * @description linux-51b2ee7d006a736a9126e8111d1f24e4fd0afaa6-compose_entry_fh 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnamlen_856, Variable vexp_858, Variable vdparent_859) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdparent_859
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dentry"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ex_path"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_858
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnamlen_856
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2")
}

predicate func_1(Variable vexp_858, Parameter vcd_855) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vexp_858
		and target_1.getRValue().(ValueFieldAccess).getTarget().getName()="fh_export"
		and target_1.getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fh"
		and target_1.getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcd_855)
}

predicate func_2(Variable vdparent_859, Variable vdchild_859) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vdchild_859
		and target_2.getAnOperand().(VariableAccess).getTarget()=vdparent_859
		and target_2.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

from Function func, Parameter vnamlen_856, Variable vexp_858, Variable vdparent_859, Variable vdchild_859, Parameter vcd_855
where
not func_0(vnamlen_856, vexp_858, vdparent_859)
and vnamlen_856.getType().hasName("int")
and vexp_858.getType().hasName("svc_export *")
and func_1(vexp_858, vcd_855)
and vdparent_859.getType().hasName("dentry *")
and func_2(vdparent_859, vdchild_859)
and vdchild_859.getType().hasName("dentry *")
and vcd_855.getType().hasName("nfsd3_readdirres *")
and vnamlen_856.getParentScope+() = func
and vexp_858.getParentScope+() = func
and vdparent_859.getParentScope+() = func
and vdchild_859.getParentScope+() = func
and vcd_855.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
