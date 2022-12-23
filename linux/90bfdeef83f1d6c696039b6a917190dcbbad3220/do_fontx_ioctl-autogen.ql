/**
 * @name linux-90bfdeef83f1d6c696039b6a917190dcbbad3220-do_fontx_ioctl
 * @id cpp/linux/90bfdeef83f1d6c696039b6a917190dcbbad3220/do-fontx-ioctl
 * @description linux-90bfdeef83f1d6c696039b6a917190dcbbad3220-do_fontx_ioctl 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vop_489) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="op"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_489
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_3(Parameter vop_489) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_489
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2147483648")
}

predicate func_4(Parameter vop_489) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_489
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="8")
}

predicate func_5(Parameter vop_489, Variable vcfdarg_491) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_489
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="charheight"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfdarg_491)
}

predicate func_6(Parameter vop_489, Variable vcfdarg_491) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="charcount"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_489
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="charcount"
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfdarg_491)
}

predicate func_7(Parameter vop_489, Variable vcfdarg_491) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_489
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="chardata"
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfdarg_491)
}

predicate func_8(Variable vi_492) {
	exists(IfStmt target_8 |
		target_8.getCondition().(VariableAccess).getTarget()=vi_492
		and target_8.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vi_492)
}

predicate func_9(Parameter vop_489, Variable vcfdarg_491) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="charheight"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfdarg_491
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_489)
}

predicate func_10(Parameter vop_489, Variable vcfdarg_491) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="charcount"
		and target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfdarg_491
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="charcount"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_489)
}

predicate func_11(Parameter vuser_cfd_488, Variable vcfdarg_491) {
	exists(IfStmt target_11 |
		target_11.getCondition().(FunctionCall).getTarget().hasName("copy_to_user")
		and target_11.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vuser_cfd_488
		and target_11.getCondition().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcfdarg_491
		and target_11.getCondition().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_11.getCondition().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="16"
		and target_11.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-14"
		and target_11.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="14")
}

predicate func_12(Function func) {
	exists(ReturnStmt target_12 |
		target_12.getExpr().(Literal).getValue()="0"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Variable vfg_console, Variable vvc_cons) {
	exists(ValueFieldAccess target_13 |
		target_13.getTarget().getName()="d"
		and target_13.getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvc_cons
		and target_13.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vfg_console)
}

from Function func, Variable vfg_console, Parameter vuser_cfd_488, Parameter vop_489, Variable vcfdarg_491, Variable vi_492, Variable vvc_cons
where
func_2(vop_489)
and func_3(vop_489)
and func_4(vop_489)
and func_5(vop_489, vcfdarg_491)
and func_6(vop_489, vcfdarg_491)
and func_7(vop_489, vcfdarg_491)
and func_8(vi_492)
and func_9(vop_489, vcfdarg_491)
and func_10(vop_489, vcfdarg_491)
and func_11(vuser_cfd_488, vcfdarg_491)
and func_12(func)
and func_13(vfg_console, vvc_cons)
and vfg_console.getType().hasName("int")
and vuser_cfd_488.getType().hasName("consolefontdesc *")
and vop_489.getType().hasName("console_font_op *")
and vcfdarg_491.getType().hasName("consolefontdesc")
and vi_492.getType().hasName("int")
and vvc_cons.getType().hasName("vc[63]")
and not vfg_console.getParentScope+() = func
and vuser_cfd_488.getParentScope+() = func
and vop_489.getParentScope+() = func
and vcfdarg_491.getParentScope+() = func
and vi_492.getParentScope+() = func
and not vvc_cons.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
