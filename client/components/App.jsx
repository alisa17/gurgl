import React from 'react'

import Header from './Header'
import SignUpFormContainer from '../containers/SignUpFormContainer'

import Collection from './Collection'
import SingleView from './SingleView'
import Faq from './Faq'
import Footer from './Footer'

import {HashRouter as Router, Route} from 'react-router-dom'

const App = () =>
   (
   <Router>
      <div className='app'>
         <Header />
         <Route path="/signup" component= {SignUpFormContainer} />
         <Route path="/collection" component= {Collection} />
         <Route path="/singleview" component= {SingleView} />
         <Route path="/faq" component= {Faq} />
         <Footer />
      </div>
   </Router>
)

export default App
