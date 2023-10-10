/**
 * @name php-78bd3477745f1ada9578a79f61edb41886bec1cb-phar_detect_phar_fname_ext
 * @id cpp/php/78bd3477745f1ada9578a79f61edb41886bec1cb/phar-detect-phar-fname-ext
 * @description php-78bd3477745f1ada9578a79f61edb41886bec1cb-ext/phar/phar.c-phar_detect_phar_fname_ext CVE-2019-9021
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpos_1899) {
	exists(SubExpr target_0 |
		target_0.getLeftOperand() instanceof SubExpr
		and target_0.getRightOperand() instanceof Literal
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("memchr")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpos_1899
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="46"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof AddExpr)
}

predicate func_1(Parameter vfilename_len_1897, Variable vpos_1899, Parameter vfilename_1897, SubExpr target_1) {
		target_1.getLeftOperand().(VariableAccess).getTarget()=vfilename_len_1897
		and target_1.getRightOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vpos_1899
		and target_1.getRightOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vfilename_1897
}

predicate func_3(Variable vpos_1899, AddExpr target_3) {
		target_3.getAnOperand() instanceof SubExpr
		and target_3.getAnOperand() instanceof Literal
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("memchr")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpos_1899
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="46"
}

from Function func, Parameter vfilename_len_1897, Variable vpos_1899, Parameter vfilename_1897, SubExpr target_1, AddExpr target_3
where
not func_0(vpos_1899)
and func_1(vfilename_len_1897, vpos_1899, vfilename_1897, target_1)
and func_3(vpos_1899, target_3)
and vfilename_len_1897.getType().hasName("int")
and vpos_1899.getType().hasName("const char *")
and vfilename_1897.getType().hasName("const char *")
and vfilename_len_1897.getParentScope+() = func
and vpos_1899.getParentScope+() = func
and vfilename_1897.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
